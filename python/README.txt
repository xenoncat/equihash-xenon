
  Python 3 extension for Xenoncat's Equihash solver
 ===================================================

This folder contains a Python 3 extension module, enabling
direct invocation of Xenoncat's Equihash solver from Python programs.

This only works with Linux and only on a x86_64 platform.


  Compiling
  ---------

Go to the 'python' folder and type:

  python3 setup.py build

The setup script should automatically invoke ext/Makefile to
compile Xenoncat's assembler sources into object files,
then invoke the C compiler to build the Python extension.


  Testing
  -------

Within the 'python' folder, type:

  python3 testbench.py

Command-line options are available to choose the number of iterations,
select the AVX instruction set, enable or disable huge pages.


  Support modules
  ---------------

blake2b.py  is a pure Python module implementing the BLAKE2b hash function.
validate.py is a pure Python module for validating Equihash solutions.

--
