format elf64
public EhPrepare as 'EhPrepare_avx1'
public EhSolver  as 'EhSolver_avx1'

include "struct.inc"
include "params.inc"
include "struct_eh.inc"
include "macro_eh.asm"

section '.text' executable align 64
include "proc_ehprepare_avx1.asm"
include "proc_ehsolver_avx1.asm"

section '.data' writeable align 64
include "data_blake2b.asm"
