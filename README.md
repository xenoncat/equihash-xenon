# equihash-xenon
Equihash proof-of-work solvers

cd Linux/demo  
make  
./solver_avx2

# API:
 #define CONTEXT_SIZE 178033152  
Application should allocate CONTEXT_SIZE bytes of memory as context for the solver. Memory alignment should be 4096. Failure to align by 32 will cause general protection exception.  
Multiple threads can be launched with separate context to solve multiple instances of equihash.  
Consider allocating HugePage (2MiB) for performance.

void EhPrepare(void *context, void *input);  
EhPrepare takes in 136 bytes of input. The remaining 4 bytes of input is fed as nonce to EhSolver.  
EhPrepare saves midstate in context, EhSolver can then be called repeatedly with different nonce.  
context does not need to be initialized by the caller.

int32_t EhSolver(void *context, uint32_t nonce);  
Conversion between uint32_t nonce and the byte array of block header is little endian byte order.  
nonce = *(uint32_t *)(inputheader+136);  
Return value is the number of solutions.  
First solution is located at context byte 0.  
Second solution is located at context byte 1344.  
And so on.