PUBLIC u_iret

PUBLIC u_cmp_8
PUBLIC u_cmp_16
PUBLIC u_cmp_32
PUBLIC u_cmp_64



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


u_cmp_8 PROC ;; eflags, ptr, value
    pushfq
    push rcx
    popfq
    cmp [rdx], r8b
    pushfq
    pop rax
    popfq
    ret
u_cmp_8 ENDP

u_cmp_16 PROC ;; eflags, ptr, value
    pushfq
    push rcx
    popfq
    cmp [rdx], r8w
    pushfq
    pop rax
    popfq
    ret

u_cmp_16 ENDP

u_cmp_32 PROC ;; eflags, ptr, value
    pushfq
    push rcx
    popfq
    cmp [rdx], r8d
    pushfq
    pop rax
    popfq
    ret
u_cmp_32 ENDP

u_cmp_64 PROC ;; eflags, ptr, value
    pushfq
    push rcx
    popfq
    cmp [rdx], r8
    pushfq
    pop rax
    popfq
    ret
u_cmp_64 ENDP

end