PUBLIC u_iret

PUBLIC u_cmp_8_sp
PUBLIC u_cmp_16_sp
PUBLIC u_cmp_32_sp
PUBLIC u_cmp_64_sp


PUBLIC u_cmp_8_dp
PUBLIC u_cmp_16_dp
PUBLIC u_cmp_32_dp
PUBLIC u_cmp_64_dp


PUBLIC u_test_8_sp
PUBLIC u_test_16_sp
PUBLIC u_test_32_sp
PUBLIC u_test_64_sp

PUBLIC u_test_8_dp
PUBLIC u_test_16_dp
PUBLIC u_test_32_dp
PUBLIC u_test_64_dp



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


u_cmp_8_sp PROC ;; eflags, ptr, value
    pushfq
    push rcx
    popfq
    cmp byte ptr [rdx], r8b
    pushfq
    pop rax
    popfq
    ret
u_cmp_8_sp ENDP

u_cmp_16_sp PROC ;; eflags, ptr, value
    pushfq
    push rcx
    popfq
    cmp word ptr [rdx], r8w
    pushfq
    pop rax
    popfq
    ret

u_cmp_16_sp ENDP

u_cmp_32_sp PROC ;; eflags, ptr, value
    pushfq
    push rcx
    popfq
    cmp dword ptr [rdx], r8d
    pushfq
    pop rax
    popfq
    ret
u_cmp_32_sp ENDP

u_cmp_64_sp PROC ;; eflags, ptr, value
    pushfq
    push rcx
    popfq
    cmp qword ptr [rdx], r8
    pushfq
    pop rax
    popfq
    ret
u_cmp_64_sp ENDP


u_cmp_8_dp PROC ;; eflags, ptr, value
    pushfq
    push rcx
    popfq
    cmp r8b, byte ptr [rdx]
    pushfq
    pop rax
    popfq
    ret
u_cmp_8_dp ENDP

u_cmp_16_dp PROC ;; eflags, ptr, value
    pushfq
    push rcx
    popfq
    cmp r8w,word ptr [rdx]
    pushfq
    pop rax
    popfq
    ret
u_cmp_16_dp ENDP

u_cmp_32_dp PROC ;; eflags, ptr, value
    pushfq
    push rcx
    popfq
    cmp r8d, dword ptr [rdx]
    pushfq
    pop rax
    popfq
    ret
u_cmp_32_dp ENDP

u_cmp_64_dp PROC ;; eflags, ptr, value
    pushfq
    push rcx
    popfq
    cmp r8, qword ptr [rdx]
    pushfq
    pop rax
    popfq
    ret
u_cmp_64_dp ENDP



u_test_8_sp PROC ;; eflags, ptr, value
    pushfq
    push rcx
    popfq
    test byte ptr [rdx], r8b
    pushfq
    pop rax
    popfq
    ret
u_test_8_sp ENDP

u_test_16_sp PROC ;; eflags, ptr, value
    pushfq
    push rcx
    popfq
    test word ptr [rdx], r8w
    pushfq
    pop rax
    popfq
    ret

u_test_16_sp ENDP

u_test_32_sp PROC ;; eflags, ptr, value
    pushfq
    push rcx
    popfq
    test dword ptr [rdx], r8d
    pushfq
    pop rax
    popfq
    ret
u_test_32_sp ENDP

u_test_64_sp PROC ;; eflags, ptr, value
    pushfq
    push rcx
    popfq
    test qword ptr [rdx], r8
    pushfq
    pop rax
    popfq
    ret
u_test_64_sp ENDP


u_test_8_dp PROC ;; eflags, ptr, value
    pushfq
    push rcx
    popfq
    test r8b, byte ptr [rdx]
    pushfq
    pop rax
    popfq
    ret
u_test_8_dp ENDP

u_test_16_dp PROC ;; eflags, ptr, value
    pushfq
    push rcx
    popfq
    test r8w,word ptr [rdx]
    pushfq
    pop rax
    popfq
    ret
u_test_16_dp ENDP

u_test_32_dp PROC ;; eflags, ptr, value
    pushfq
    push rcx
    popfq
    test r8d, dword ptr [rdx]
    pushfq
    pop rax
    popfq
    ret
u_test_32_dp ENDP

u_test_64_dp PROC ;; eflags, ptr, value
    pushfq
    push rcx
    popfq
    test r8, qword ptr [rdx]
    pushfq
    pop rax
    popfq
    ret
u_test_64_dp ENDP

end