; This function dynamically builds a standard Windows x64 call frame
; from an argument vector and then issues the syscall.
; 
; Externally visible as:
;   extern int nt_syscall(uint32_t syscall_number, ULONGLONG *args, int arg_count);
; where:
;   ECX = syscall_number
;   RDX = pointer to an array of ULONGLONG arguments
;   R8D = arg_count (total count of arguments provided in the array)
;
; The normal Windows calling convention expects:
;   - The first four parameters in RCX, RDX, R8, R9.
;   - The caller to reserve 32 bytes (shadow space) on the stack.
;   - Any additional (extra) parameters to be passed on the stack,
;     located after the shadow space (i.e. at offsets 40, 48, …)
;
; Because this stub is “dynamic” (it gets its arguments from an array),
; we must reconstruct that typical stack frame: we copy the first 4 args
; into the registers and then, if there are extra parameters, allocate on the
; stack enough space for a dummy return address (8 bytes), shadow space (32 bytes),
; plus room to copy the extra arguments (each 8 bytes) in order.

global nt_syscall
section .text
nt_syscall:
    ; [Entry]
    ; ECX = syscall_number
    ; RDX = pointer to args array
    ; R8D = arg_count

    ; Save nonvolatile registers we will use:
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14

    mov  r12d, r8d

    mov  r13d, ecx

    mov  rsi, rdx
    mov  edi, r8d

    mov  rcx, [rsi + 0*8]   ; 1st argument → RCX
    mov  rdx, [rsi + 1*8]   ; 2nd argument → RDX
    mov  r8,  [rsi + 2*8]   ; 3rd argument → R8
    mov  r9,  [rsi + 3*8]   ; 4th argument → R9

    mov  r14d, edi
    cmp  r14d, 4
    jle  .no_extra
    sub  r14d, 4

.no_extra:
    mov  eax, r14d
    shl  eax, 3
    add  eax, 40

    sub  rsp, rax

    mov  qword [rsp], 0

    cmp  r14d, 0
    je   .do_syscall
    xor  rbx, rbx

.copy_loop:
    mov  rdx, [rsi + (4 + rbx)*8]

    mov  qword [rsp + 40 + rbx*8], rdx
    inc  rbx
    cmp  ebx, r14d
    jl   .copy_loop

.do_syscall:
    mov  r10, rcx

    mov eax, r13d
    syscall
    mov r13d, eax

    mov  eax, r14d
    shl  eax, 3
    add  eax, 40
    add  rsp, rax

    mov eax, r13d

    pop  r14
    pop  r13
    pop  r12
    pop  rdi
    pop  rsi
    pop  rbx
    ret
