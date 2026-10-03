bits 64
section .text 

global find_rsp
global find_rbp
global find_rip
global call_syscall4
global call_syscall8
global call_syscall11

extern g_SyscallNumber
extern g_SyscallAddress

find_rsp:
  lea rax, [rsp+8]
  ret

find_rbp: 
  mov rax, rbp
  ret

find_rip:
  mov rax, [rsp]
  ret

call_syscall4:
call_syscall8:
call_syscall11:
  mov r10, rcx
  mov eax, dword [g_SyscallNumber]
  jmp qword [g_SyscallAddress]
  ret

