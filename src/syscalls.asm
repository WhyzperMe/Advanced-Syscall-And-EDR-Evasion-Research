; minimalistic asm code
.code
IndirectSyscall6 PROC
    mov rax, rcx
    mov r10, rdx
    mov rdx, r8
    mov r8, r9
    mov r9, [rsp + 28h]
    mov rcx, [rsp + 30h]
    mov [rsp + 28h], rcx
    mov rcx, [rsp + 38h]
    mov [rsp + 30h], rcx
    mov rcx, [rsp + 40h]
    jmp rcx
IndirectSyscall6 ENDP

IndirectSyscall5 PROC
    mov rax, rcx
    mov r10, rdx
    mov rdx, r8
    mov r8, r9
    mov r9, [rsp + 28h]
    mov rcx, [rsp + 30h]
    mov [rsp + 28h], rcx
    mov rcx, [rsp + 38h]
    jmp rcx
IndirectSyscall5 ENDP

END