# Xenon-Mac

Running

```
make
./solver_avx1
```

Currently, ASLR must be disabled for the linker to produce working executables.
Otherwise it will segfault. If you wish to debug, make sure to turn on ASLR
on lldb or gdb, otherwise the bug will not show up.

It appears that the blake2sigma data is referenced at the wrong address when
ASLR is enabled. The register r9 should have the address of blake2sigma
at +595, but in the ASLR case all the addresses have been shifted. This is
the point of ASLR, but I'm not sure how to fix the offset here.

The affected asm code is:

proc_ehprepare_avx1.asm:121
```
_LoopBlakeMsgSched:
movzx eax, byte [r9+r10]
mov rax, [rsi+rax*8]
```

ASLR On (Seg Faulting)
```
* thread #1: tid = 0x4ad7c1, 0x0000000001c366d3 solver_avx1`EhPrepare + 595, queue = 'com.apple.main-thread', stop reason = EXC_BAD_ACCESS (code=1, address=0x4051c0)
  * frame #0: 0x0000000001c366d3 solver_avx1`EhPrepare + 595
    frame #1: 0x00007fff5e3c9f90
    frame #2: 0x0000000001c3606d solver_avx1`main + 589
    frame #3: 0x00007fff8d6695c9 libdyld.dylib`start + 1
    frame #4: 0x00007fff8d6695c9 libdyld.dylib`start + 1
(lldb) f 0
frame #0: 0x0000000001c366d3 solver_avx1`EhPrepare + 595
solver_avx1`EhPrepare:
->  0x1c366d3 <+595>: movzbl (%r9,%r10), %eax
    0x1c366d8 <+600>: movq   (%rsi,%rax,8), %rax
    0x1c366dc <+604>: movq   %rax, (%r8,%r10,8)
    0x1c366e0 <+608>: addl   $0x1, %r10d
General Purpose Registers:
       rax = 0x000000000000000a
       rbx = 0x0000000001c39da8  "Preparing..."
       rcx = 0x0000000000000000
       rdx = 0x00007fff722c7128  __sFX + 248
       rdi = 0x0000000001c3c000
       rsi = 0x00007fff5e3ca110
       rbp = 0x00007fff5e3c9f90
       rsp = 0x00007fff5e3c9d98
        r8 = 0x00007fff5e3c9da0
        r9 = 0x00000000004051c0
       r10 = 0x0000000000000000
       r11 = 0x0000000000000246
       r12 = 0x0000000000000000
       r13 = 0x0000000000000000
       r14 = 0x0000000000000000
       r15 = 0x0000000000000000
       rip = 0x0000000001c366d3  solver_avx1`EhPrepare + 595
    rflags = 0x0000000000010246
        cs = 0x000000000000002b
        fs = 0x0000000000000000
        gs = 0x0000000000000000
```
ASLR Off (Just a breakpoint)
```
* thread #1: tid = 0x4b738f, 0x00000000004016d3 solver_avx1`EhPrepare + 595, queue = 'com.apple.main-thread', stop reason = breakpoint 3.1
    frame #0: 0x00000000004016d3 solver_avx1`EhPrepare + 595
solver_avx1`EhPrepare:
->  0x4016d3 <+595>: movzbl (%r9,%r10), %eax
    0x4016d8 <+600>: movq   (%rsi,%rax,8), %rax
    0x4016dc <+604>: movq   %rax, (%r8,%r10,8)
    0x4016e0 <+608>: addl   $0x1, %r10d
General Purpose Registers:
       rax = 0x000000000000000a
       rbx = 0x0000000000404da8  "Preparing..."
       rcx = 0x0000000000000000
       rdx = 0x00007fff722c7128  __sFX + 248
       rdi = 0x0000000001000000
       rsi = 0x00007fff5fbff120
       rbp = 0x00007fff5fbfefa0
       rsp = 0x00007fff5fbfeda8
        r8 = 0x00007fff5fbfedb0
        r9 = 0x00000000004051c0  .data + 320
       r10 = 0x0000000000000000
       r11 = 0x0000000000000246
       r12 = 0x0000000000000000
       r13 = 0x0000000000000000
       r14 = 0x0000000000000000
       r15 = 0x0000000000000000
       rip = 0x00000000004016d3  solver_avx1`EhPrepare + 595
    rflags = 0x0000000000000246
        cs = 0x000000000000002b
        fs = 0x0000000000000000
        gs = 0x0000000000000000
```
