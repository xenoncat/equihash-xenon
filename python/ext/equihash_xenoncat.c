/*
 * Python 3 extension module for Xenoncat's Equihash solver.
 */

#include <stddef.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <sys/mman.h>
#include <cpuid.h>
#include <Python.h>


#define EQXC_CONTEXT_SIZE   178033152
#define EQXC_CONTEXT_ALLOC  (EQXC_CONTEXT_SIZE+4096)


/* Declare assembler functions. */
void    EhPrepare_avx1(void *context, void *input);
void    EhPrepare_avx2(void *context, void *input);
int32_t EhSolver_avx1(void *context, uint32_t nonce);
int32_t EhSolver_avx2(void *context, uint32_t nonce);


/* Return highest supported AVX version. (0 = no AVX, 1 = AVX1, 2 = AVX2) */
static int check_avx_supported(void)
{
    unsigned int eax, ebx, ecx, edx;

    __cpuid(1, eax, ebx, ecx, edx);

    if (((ecx >> 28) & 1) == 0) {
        /* AVX not supported */
        return 0;
    }

    __cpuid(0, eax, ebx, ecx, edx);

    if (eax < 7) {
        /* CPUID page 7 not supported (implies no AVX2) */
        return 1;
    }

    __cpuid_count(7, 0, eax, ebx, ecx, edx);

    if (((ebx >> 5) & 1) == 0) {
        /* AVX2 not supported */
        return 1;
    }

    return 2;
}


typedef struct {
    PyObject_HEAD
    void * context_alloc;
    void * context;
    int    avxversion;
    int    hugetlb;
    int    prepared;
} eqxc_data;


static int eqxc_init(PyObject *self, PyObject *args, PyObject *kwds)
{
    eqxc_data *pdata = (eqxc_data *)self;

    pdata->context_alloc = NULL;
    pdata->context = NULL;
    pdata->avxversion = 0;
    pdata->hugetlb = 0;
    pdata->prepared = 0;

    static const char * keywords[] = { "avxversion", "hugetlb", NULL };
    int avxversion = -1;
    int hugetlb = -1;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|ii", (char**)keywords,
                                     &avxversion, &hugetlb)) {
        return -1;
    }

    if (avxversion != -1 &&
        avxversion != 1 &&
        avxversion != 2) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid value for avxversion (must be 1 or 2 or -1)");
        return -1;
    }

    if (hugetlb != -1 &&
        hugetlb != 0 &&
        hugetlb != 1) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid value for hugetlb (must be 0 or 1 or -1)");
        return -1;
    }

    pdata->avxversion = check_avx_supported();
    if (pdata->avxversion == 0) {
        PyErr_SetString(PyExc_SystemError,
                        "This module requires a CPU with AVX support");
        return -1;
    }

    if (avxversion == 2 && pdata->avxversion < 2) {
        PyErr_SetString(PyExc_SystemError, "CPU does not support AVX2");
        return -1;
    }
    
    if (avxversion != -1) {
        pdata->avxversion = avxversion;
    }

    if (hugetlb != 0) {
        pdata->hugetlb = 1;
        pdata->context_alloc = mmap(NULL,
                                    EQXC_CONTEXT_ALLOC,
                                    PROT_READ | PROT_WRITE,
                                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB,
                                    -1, 0);
    }

    if (hugetlb == 0 ||
        (hugetlb == -1 && pdata->context_alloc == MAP_FAILED)) {
        pdata->hugetlb = 0;
        pdata->context_alloc = mmap(NULL,
                                    EQXC_CONTEXT_ALLOC,
                                    PROT_READ | PROT_WRITE,
                                    MAP_PRIVATE | MAP_ANONYMOUS,
                                    -1, 0);
    }

    if (pdata->context_alloc == MAP_FAILED) {
        pdata->context_alloc = NULL;
        PyErr_SetFromErrno(PyExc_OSError);
        return -1;
    }

    pdata->context =
        (void*) (((unsigned long)(pdata->context_alloc) + 4095) & (~(4095UL)));

    return 0;
}


static void eqxc_dealloc(PyObject *self)
{
    eqxc_data *pdata = (eqxc_data *)self;

    if (pdata->context_alloc != NULL) {
        munmap(pdata->context_alloc, EQXC_CONTEXT_ALLOC);
        pdata->context_alloc = NULL;
        pdata->context = NULL;
    }

    Py_TYPE(self)->tp_free(self);
}


static PyObject * eqxc_prepare(PyObject *self, PyObject *args)
{
    eqxc_data *pdata = (eqxc_data *)self;
    assert(pdata->context != NULL);

    PyObject *input;
    if (!PyArg_ParseTuple(args, "S", &input)) {
        return NULL;
    }

    if (PyBytes_Size(input) != 136) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid input length (need exactly 136 bytes)");
        return NULL;
    }

    const char *inputdata = PyBytes_AsString(input);
    if (inputdata == NULL) {
        return NULL;
    }

    uint32_t inputbuf[34];
    memcpy(inputbuf, inputdata, 136);

    Py_BEGIN_ALLOW_THREADS

    if (pdata->avxversion == 2) {
        EhPrepare_avx2(pdata->context, inputbuf);
    } else {
        EhPrepare_avx1(pdata->context, inputbuf);
    }

    Py_END_ALLOW_THREADS

    pdata->prepared = 1;

    Py_RETURN_NONE;
}


static PyObject * eqxc_solve(PyObject *self, PyObject *args)
{
    eqxc_data *pdata = (eqxc_data *)self;
    assert(pdata->context != NULL);

    unsigned long nonce;
    if (!PyArg_ParseTuple(args, "k", &nonce)) {
        return NULL;
    }

    if (!pdata->prepared) {
        PyErr_SetString(PyExc_ValueError,
                        "Must call prepare() before calling solve()");
        return NULL;
    }

    int nsolutions;

    Py_BEGIN_ALLOW_THREADS

    if (pdata->avxversion == 2) {
        nsolutions = EhSolver_avx2(pdata->context, nonce);
    } else {
        nsolutions = EhSolver_avx1(pdata->context, nonce);
    }

    Py_END_ALLOW_THREADS

    PyObject *list = PyList_New(nsolutions);
    if (list == NULL) {
        return NULL;
    }

    for (int i = 0; i < nsolutions; i++) {
        const char *p = ((const char *)pdata->context) + (1344 * i);
        PyObject *sol = PyBytes_FromStringAndSize(p, 1344);
        if (sol == NULL) {
            Py_DECREF(list);
            return NULL;
        }
        if (PyList_SetItem(list, i, sol) < 0) {
            Py_DECREF(list);
            return NULL;
        }
    }

    return list;
}


static PyObject * eqxc_get_avxversion(PyObject *self, void *pyctx)
{
    eqxc_data *pdata = (eqxc_data *)self;
    return PyLong_FromLong(pdata->avxversion);
}


static PyObject * eqxc_get_hugetlb(PyObject *self, void *pyctx)
{
    eqxc_data *pdata = (eqxc_data *)self;
    return PyBool_FromLong(pdata->hugetlb);
}


static PyObject *eqxc_get_debugdata(PyObject *self, void *pyctx)
{
    eqxc_data *pdata = (eqxc_data *)self;
    assert(pdata->context != NULL);

    const uint64_t *debug = ((const uint64_t *)pdata->context) + 12800;
    const unsigned int nitem = 21;

    PyObject *tuple = PyTuple_New(nitem);
    if (tuple == NULL) {
        return NULL;
    }

    for (unsigned int i = 0; i < nitem; i++) {
        PyObject *v = PyLong_FromUnsignedLong(debug[1+i]);
        if (v == NULL) {
            Py_DECREF(tuple);
            return NULL;
        }
        if (PyTuple_SetItem(tuple, i, v) != 0) {
            Py_DECREF(tuple);
            return NULL;
        }
    }

    return tuple;
}


static PyMethodDef eqxc_methods[] = {
    { "prepare", eqxc_prepare, METH_VARARGS,
      "prepare(input)\n\n"
      "Prepare the solver for new input data.\n\n"
      "  input     -- 'bytes' object containing 136 bytes of input.\n" },
    { "solve",   eqxc_solve,   METH_VARARGS,
      "solve(nonce)\n\n"
      "Run the solver on the specified nonce.\n\n"
      "  nonce     -- 32-bit unsigned integer, interpreted as 4 nonce bytes\n"
      "               in little-endian order.\n\n"
      "Return a list of solutions, each solution represented as\n"
      "a 'bytes' object with 1344 bytes.\n" },
    { NULL, NULL, 0, NULL } };


static PyGetSetDef eqxc_getset[] = {
    { "avxversion", eqxc_get_avxversion, NULL,
      "AVX version used by engine (1 or 2).",
      NULL },
    { "hugetlb", eqxc_get_hugetlb, NULL,
      "True when using huge pages, otherwise False.",
      NULL },
    { "debugdata", eqxc_get_debugdata, NULL,
      "List of debug data items from assembler code.\n"
      "See struct_eh.asm for the meaning of these numbers.",
      NULL },
    { NULL, NULL, NULL, NULL, NULL } };


static PyTypeObject eqxc_type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "equihash_xenoncat.EquihashXenoncat", /* tp_name */
    sizeof(eqxc_data),          /* tp_basicsize */
    0,                          /* tp_itemsize */
    eqxc_dealloc,               /* tp_dealloc */
    0,                          /* tp_print */
    0,                          /* tp_getattr */
    0,                          /* tp_setattr */
    0,                          /* tp_compare     */
    0,                          /* tp_repr        */
    0,                          /* tp_as_number   */
    0,                          /* tp_as_sequence */
    0,                          /* tp_as_mapping  */
    0,                          /* tp_hash        */
    0,                          /* tp_call        */
    0,                          /* tp_str         */
    0,                          /* tp_getattro    */
    0,                          /* tp_setattro    */
    0,                          /* tp_as_buffer   */
    Py_TPFLAGS_DEFAULT,         /* tp_flags       */
    "EquihashXenoncat(avxversion=-1, hugetlb=-1)\n\n"
    "Construct new Equihash engine and allocate memory.\n\n"
    "  avxversion    -- Select AVX instruction set,\n"
    "                   1 = AVX1, 2 = AVX2, -1 = autodetect.\n"
    "  hugetlb       -- Allocate huge pages (faster),\n"
    "                   0 = normal pages, 1 = huge pages, -1 = autodetect.\n"
};


static PyObject * eqh_checkAvxSupported(PyObject *self, PyObject *args)
{
    int avxversion = check_avx_supported();
    return PyLong_FromLong(avxversion);
}


static PyMethodDef eqh_methods[] = {
    { "checkAvxSupported", eqh_checkAvxSupported, METH_NOARGS,
      "checkAvxSupported()\n\n"
      "Check AVX version supported by CPU.\n\n"
      "Return 2 if the CPU supports AVX2, 1 if it supports only AVX1.\n"
      "Return 0 if the CPU does not support AVX.\n" },
    { NULL, NULL, 0, NULL } };


static PyModuleDef eqh_module = {
    PyModuleDef_HEAD_INIT,      /* m_base */
    "equihash_xenoncat",        /* m_name */
    NULL,                       /* m_doc */
    -1,                         /* m_size */
    eqh_methods,                /* m_methods */
    NULL,                       /* m_reload */
    NULL,                       /* m_traverse */
    NULL,                       /* m_clear */
    NULL };                     /* m_free */


PyMODINIT_FUNC
PyInit_equihash_xenoncat(void)
{
    PyObject *m;

    eqxc_type.tp_new      = PyType_GenericNew;
    eqxc_type.tp_init     = eqxc_init;
    eqxc_type.tp_methods  = eqxc_methods;
    eqxc_type.tp_getset   = eqxc_getset;

    if (PyType_Ready(&eqxc_type) < 0)
        return NULL;

    m = PyModule_Create(&eqh_module);
    if (m == NULL)
        return NULL;

    Py_INCREF(&eqxc_type);
    PyModule_AddObject(m, "EquihashXenoncat", (PyObject *)&eqxc_type);

    return m;
}

