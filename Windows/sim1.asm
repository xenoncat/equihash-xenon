format PE64 console 5.0
entry start
MEM_LARGE_PAGES = 20000000h

include 'win64a.inc'
include 'params.inc'
include 'struct_eh.inc'
include 'macro_eh.asm'

section '.text' code readable executable

start:
mov eax, esp
cmp rax, rsp
jne _Exit

sub esp, 0x108
and esp, -32
frame

call [GetCurrentThread]
mov rcx, rax
mov edx, 1
call [SetThreadAffinityMask]

xor ecx, ecx
mov edx, sizeof.EH
mov r8d, MEM_RESERVE + MEM_COMMIT + MEM_LARGE_PAGES
mov r9d, PAGE_READWRITE
call [VirtualAlloc]
test rax, rax
jnz _MemAllocOK

mov ecx, szLargePageFailed
call [puts]

xor ecx, ecx
mov edx, sizeof.EH
mov r8d, MEM_RESERVE + MEM_COMMIT
mov r9d, PAGE_READWRITE
call [VirtualAlloc]
test rax, rax
jnz _MemAllocOK

mov ecx, szMemAllocFailed
call [puts]
jmp _Exit

_MemAllocOK:
mov [hMem1], rax

lea rcx, [rsp+0x78]
call [QueryPerformanceFrequency]
mov ecx, fmtqpcfreq
mov rdx, [rsp+0x78]
call [printf]


xor eax, eax
mov [rsp+0x50], eax
_LoopNonce1:

lea rcx, [rsp+0x80]
call [QueryPerformanceCounter]
rdtsc
shl rdx, 32
or rax, rdx
mov [rsp+0x88], rax

mov rcx, [hMem1]
mov edx, t1
call _ProcEhPrepare

mov rcx, [hMem1]
mov edx, dword [t1+136]
add edx, [rsp+0x50]
call _ProcEhSolver
mov ebx, eax

lea rcx, [rsp+0x90]
call [QueryPerformanceCounter]
rdtsc
shl rdx, 32
or rax, rdx
mov [rsp+0x98], rax
;

mov ecx, fmtds
mov edx, ebx
call [printf]

;
mov rax, [rsp+0x78]
xor edx, edx
mov ecx, 1000
div rcx
mov [rsp+0x70], rax
mov rax, [rsp+0x90]
sub rax, [rsp+0x80]
jz _DeltaTimeZero
mov [rsp+0x20], rax
xor edx, edx
div qword [rsp+0x70]
mov rdx, rax
mov ecx, fmtTime
call [printf]

mov eax, [rsp+0x50]
add eax, 1
mov [rsp+0x50], eax
cmp eax, 20
jb _LoopNonce1

;rdtsc*qpf/qpc
mov rax, [rsp+0x98]
sub rax, [rsp+0x88]
mul qword [rsp+0x78]
div qword [rsp+0x20]
mov ecx, fmtrdtscmeasured
mov rdx, rax
call [printf]

_DeltaTimeZero:
;mov rbp, [hMem1]

_Panic:
mov rcx, [hMem1]
xor edx, edx
mov r8d, MEM_RELEASE	;0x8000
call [VirtualFree]

_Exit:
xor ecx, ecx
call [ExitProcess]

align 64
include "proc_ehprepare.asm"
include "proc_ehsolver.asm"

endf

section '.data' data readable writeable
fmtdn db "%d", 0Dh, 0Ah, 0
fmtds db "%d ", 0
fmtxn db "%x", 0Dh, 0Ah, 0
fmtllxn db "%016llx", 0Dh, 0Ah, 0
fmtqpcfreq db "QueryPerformanceCounter frequency: %lld Hz", 0Dh, 0Ah, 0
fmtrdtscmeasured db "Measured rdtsc frequency: %lld Hz", 0Dh, 0Ah, 0
fmttimingblake db "BLAKE2b rdtsc: %lld", 0Dh, 0Ah, 0
fmttimingstage db "Stage %d, Output pairs %d, rdtsc: %lld %lld %lld %lld", 0Dh, 0Ah, 0
fmtsolution1 db "Number of solutions before duplicate removal: %d", 0Dh, 0Ah, 0
fmttimingremdup db "Duplicate removal and tree expand rdtsc: %lld", 0Dh, 0Ah, 0
fmtsolution2 db "Solutions found: %d", 0Dh, 0Ah, 0
fmtTime db "Time: %d ms", 0Dh, 0Ah, 0
szRunning db "Running solver...", 0
szLargePageFailed db "Failed to allocate Large Page, performance may be affected", 0
szMemAllocFailed db "Failed to allocate memory", 0
szoutfile db "out.bin", 0

align 64
include "data_blake2b.asm"

align 64
t1 file "t2.bin"

align 64
hMem1 rq 1

align 64
buf0 rb 512

section '.idata' import data readable writeable
library kernel32,'kernel32.dll',\
 user32,'user32.dll',\
 msvcrt,'msvcrt.dll'


include 'api\kernel32.inc'
include 'api\user32.inc'

import msvcrt,\
	printf,'printf',\
	puts,'puts'
