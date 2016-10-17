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

call [GetCurrentProcess]
mov rcx, rax
mov edx, 0x28	;TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY
lea r8d, [rsp+0x50]
call [OpenProcessToken]

xor ecx, ecx
mov edx, szSeLMP
lea r8d, [rsp+0x60]
call [LookupPrivilegeValue]

mov dword [rsp+0x5C], 1
mov dword [rsp+0x68], 2	;SE_PRIVILEGE_ENABLED
mov rcx, [rsp+0x50]	;TokenHandle
xor edx, edx		;DisableAllPrivileges
lea r8d, [rsp+0x5C]	;NewState
xor r9d, r9d		;BufferLength
xor eax, eax
mov qword [rsp+0x20], rax	;PreviousState
mov qword [rsp+0x28], rax	;ReturnLength
call [AdjustTokenPrivileges]

xor ecx, ecx
mov edx, (sizeof.EH+0x1fffff) and -0x200000
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

mov rcx, [hMem1]
mov edx, t1
call _ProcEhPrepare

lea rcx, [rsp+0x80]
call [QueryPerformanceCounter]
mov rcx, [hMem1]
xor edx, edx
call _ProcEhSolver	;Warm up run
mov ebx, eax
lea rcx, [rsp+0x90]
call [QueryPerformanceCounter]
mov rax, [rsp+0x90]
sub rax, [rsp+0x80]
imul rax, rax, 1000
xor edx, edx
mov rcx, [rsp+0x78]
div rcx
mov ecx, fmtWarmupTime
mov edx, eax
mov r8d, ebx
call [printf]

START_NONCE = 58		;arbritary number to get 19 solutions in 10 iterations (to match 1.88 solutions per run)
END_NONCE = 68
mov dword [rsp+0x50], START_NONCE
xor eax, eax
mov [rsp+0x54], eax	;accumulate solutions
mov [rsp+0x58], rax	;accumulate delta QPC

_LoopNonce1:
lea rcx, [rsp+0x80]
call [QueryPerformanceCounter]

mov rcx, [hMem1]
mov edx, [rsp+0x50]
call _ProcEhSolver
add [rsp+0x54], eax
mov ebx, eax

lea rcx, [rsp+0x90]
call [QueryPerformanceCounter]
mov rax, [rsp+0x90]
sub rax, [rsp+0x80]
add [rsp+0x58], rax
imul rax, rax, 1000
xor edx, edx
mov rcx, [rsp+0x78]
div rcx
mov ecx, fmtTime
mov edx, eax
mov r8d, ebx
call [printf]

mov eax, [rsp+0x50]
add eax, 1
mov [rsp+0x50], eax
cmp eax, END_NONCE
jb _LoopNonce1

mov rax, [rsp+0x58]
imul rax, rax, 1000
xor edx, edx
mov rcx, [rsp+0x78]
imul rcx, rcx, END_NONCE-START_NONCE
div rcx
mov edx, eax
mov ecx, fmtAvgTime
call [printf]

_Panic:
mov rcx, [hMem1]
xor edx, edx
mov r8d, MEM_RELEASE	;0x8000
call [VirtualFree]

_Exit:
xor ecx, ecx
call [ExitProcess]

align 64
include "proc_ehprepare_avx2.asm"
include "proc_ehsolver_avx2.asm"

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
fmtWarmupTime db "(Warm up) Time: %u ms, solutions: %u", 0Dh, 0Ah, 0
fmtTime db "Time: %u ms, solutions: %u", 0Dh, 0Ah, 0
fmtAvgTime db "Average time: %d ms", 0D, 0Ah, 0
szRunning db "Running solver...", 0
szSeLMP db "SeLockMemoryPrivilege",0
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
 msvcrt,'msvcrt.dll',\
 advapi32,'advapi32.dll'

include 'api\kernel32.inc'
include 'api\user32.inc'
include 'api\advapi32.inc'

import msvcrt,\
	printf,'printf',\
	puts,'puts'
