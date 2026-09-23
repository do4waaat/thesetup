bits 64
section .text 

global find_rsp
global find_rbp
global find_rip
global call_syscall
find_rsp:
  lea rax, [rsp+8]
  ret
find_rbp: 
  mov rax, rbp
  ret
find_rip:
  mov rax, [rsp]
  ret
call_syscall:
  mov r10, r8      
  mov rax, rdx     
  mov rdx, r9      
  jmp rcx          
  ret   
