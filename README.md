Kernel Anti-Cheat Emulator
SOON(tm)

Current state of the emulator won't properly load most drivers because most important functions aren't implemented.

What KACE achieved so far:
- Detect a new sneaky way of EAC detecting unloaded driver
- VGKs bruteforcing self-entry/ref of CR3's VA


Emulation detection :
- Checking if RIP is in kernel range, can be fixed by modifying pte and exposing kernel memory, will require a vuln driver. If someone wants to implement this feature, PR welcome
- EPROCESS/ETHREAD structure is implemented and put in gs:0x188, which creates the illusion that the usermode thread is a kernel thread for the emulated driver. That structure is not entirely filled and can probably be improved, PR welcome
- Wrong behavior of some API, for instance RtlRandomEx has different behavior in kernel and usermode, this can be checked to check for emulation behavior, I fixed it but if you know of any difference between ntoskrnl/ntdll that can be used to check for emulation, PR!
- Checking if current code is in ring3/ring0, can probably sigscan for such pattern. A Disasm engine would be perfect.
- PTE checking, can be emulated the second there's any access to cr0/cr4, we get notified anyway.
