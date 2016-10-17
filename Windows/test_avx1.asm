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

mov rdi, [hMem1]
lea rsi, [rdi+sizeof.EH]
xor eax, eax
_LoopPrimePageTable:
mov [rdi], eax
add rdi, 4096
cmp rdi, rsi
jb _LoopPrimePageTable

lea rcx, [rsp+0x78]
call [QueryPerformanceFrequency]
mov ecx, fmtqpcfreq
mov rdx, [rsp+0x78]
call [printf]

mov ecx, szRunning
call [puts]

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
	;add edx, 17
call _ProcEhSolver
mov ebx, eax

lea rcx, [rsp+0x90]
call [QueryPerformanceCounter]
rdtsc
shl rdx, 32
or rax, rdx
mov [rsp+0x98], rax
;
mov rbp, [hMem1]
mov ecx, fmttimingblake
mov rdx, [rbp+EH.debug+8]
sub rdx, [rbp+EH.debug]
call [printf]

if 1
lea rsi, [rbp+EH.debug+16]
mov r12, [rbp+EH.debug+8]
mov edi, 1
_LoopPrintStageTiming:
mov r9, [rsi]
mov rax, r12
mov r12, r9
sub r9, rax
mov r8d, [rsi+8]
mov ecx, fmttimingstage
mov edx, edi
call [printf]
add rsi, 16
add edi, 1
cmp edi, 10
jb _LoopPrintStageTiming
end if

mov ecx, fmtsolution1
mov edx, dword [rbp+EH.bucket0ptr]
call [printf]

mov ecx, fmttimingremdup
mov rdx, [rsi]
sub rdx, r12
call [printf]

mov ecx, fmtsolution2
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

;rdtsc*qpf/qpc
mov rax, [rsp+0x98]
sub rax, [rsp+0x88]
mul qword [rsp+0x78]
div qword [rsp+0x20]
mov ecx, fmtrdtscmeasured
mov rdx, rax
call [printf]

_DeltaTimeZero:
mov rbp, [hMem1]

if 1
mov rbp, [hMem1]
mov ecx, szoutfile	;lpFileName
mov edx, GENERIC_WRITE	;dwDesiredAccess
mov r8d, 3		;dwShareMode
xor r9d, r9d		;lpSecurityAttributes
mov eax, CREATE_ALWAYS
mov [rsp+0x20], rax	;dwCreationDisposition
xor eax, eax
mov [rsp+0x28], rax	;dwFlagsAndAttributes
mov [rsp+0x30], rax	;hTemplateFile
call [CreateFile]
mov [rsp+0x30], rax
mov rcx, [rsp+0x30]	;hFile
;mov rdx, [hMem1]	;lpBuffer
lea rdx, [rbp+EH.hashtab+1344*2]
;lea rdx, [rbp+EH.hashtab]

mov r8d, 1344		;nNumberOfBytesToWrite
;mov r8d, 1344*4
lea r9d, [rsp+0x38]	;lpNumberOfBytesWritten
xor eax, eax
mov [rsp+0x20], rax	;lpOverlapped
call [WriteFile]
mov rcx, [rsp+0x30]	;hFile
call [CloseHandle]
end if

mov rcx, [hMem1]
xor edx, edx
mov r8d, MEM_RELEASE	;0x8000
call [VirtualFree]

_Exit:
xor ecx, ecx
call [ExitProcess]

align 64
include "proc_ehprepare_avx1.asm"
include "proc_ehsolver_avx1.asm"

endf

section '.data' data readable writeable
fmtdn db "%d", 0Dh, 0Ah, 0
fmtxn db "%x", 0Dh, 0Ah, 0
fmtllxn db "%016llx", 0Dh, 0Ah, 0
fmtqpcfreq db "QueryPerformanceCounter frequency: %lld Hz", 0Dh, 0Ah, 0
fmtrdtscmeasured db "Measured rdtsc frequency: %lld Hz", 0Dh, 0Ah, 0
fmttimingblake db "BLAKE2b rdtsc: %lld", 0Dh, 0Ah, 0
fmttimingstage db "Stage %d, Output pairs %d, rdtsc: %lld", 0Dh, 0Ah, 0
fmtsolution1 db "Number of solutions before duplicate removal: %d", 0Dh, 0Ah, 0
fmttimingremdup db "Duplicate removal and tree expand rdtsc: %lld", 0Dh, 0Ah, 0
fmtsolution2 db "Solutions found: %d", 0Dh, 0Ah, 0
fmtTime db "Time: %d ms", 0Dh, 0Ah, 0
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
