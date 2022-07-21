Kernel Anti-Cheat Emulator
SOON(tm)

Current state of the emulator won't properly load most drivers because most important functions aren't implemented.

What's done: 
- Mapping of driver in usermode and start a thread on it
- Resolving of IAT/EAT
- API to monitor Write/Read to any structures
- SEH handling
- Some Anti-debug/emulation check by VGK pass now

Next steps:
- Disasm engine + CPU emulation during privileged instructions (C0d3X implemented most of it, i'll adapt and push soon)
- Dynamic translation of the binary for some patterns. (Daax idea, i might take a go at it if no one wants to do it)
- Kernel memory allocation (being done by DarkC)


Emulation detection :
- Checking if RIP is in kernel range, can be fixed by modifying pte and exposing kernel memory, will require a vuln driver. If someone wants to implement this feature, PR welcome
- EPROCESS/ETHREAD/KPCR/PRCB structure are implemented, which creates the illusion that the usermode thread is a kernel thread for the emulated driver. Those structures are not entirely filled and can probably be improved, PR welcome
- Wrong behavior of some API, for instance RtlRandomEx has different behavior in kernel and usermode, this can be checked to check for emulation behavior, I fixed it but if you know of any difference between ntoskrnl/ntdll that can be used to check for emulation, PR!
- Checking if current code is in ring3/ring0, can probably sigscan for such pattern. A Disasm engine would be perfect.
- PTE checking, can be emulated the second there's any access to cr3, we get notified anyway.
