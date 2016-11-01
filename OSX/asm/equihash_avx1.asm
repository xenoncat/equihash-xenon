format elf64
public _EhPrepare
public _EhSolver
public _testinput

include "struct.inc"
include "params.inc"
include "struct_eh.inc"
include "macro_eh.asm"

section '.text' executable align 64
include "proc_ehprepare_avx1.asm"
include "proc_ehsolver_avx1.asm"

section '.data' writeable align 64
include "data_blake2b.asm"
_testinput file "t2.bin"
