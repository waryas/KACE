PUBLIC u_iret


.CODE 

ALIGN 16

.code

u_iret PROC
    cpuid
    mov rax, [rsp+0h] ;original jmp
    mov rcx, [rsp+10h] ;original eflag
    mov rdx, [rsp+18h] ; original rsp
    push rcx
    popfq
    mov rsp, rdx
    jmp rax
u_iret ENDP
end