#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

extern DWORD g_SyscallNumber;
extern PVOID g_SyscallAddress;

DWORD64 find_rsp();
DWORD64 find_rbp();
DWORD64 find_rip();

NTSTATUS call_syscall4(PVOID arg1, PVOID arg2, PVOID arg3, PVOID arg4);
NTSTATUS call_syscall8(PVOID arg1, PVOID arg2, PVOID arg3, PVOID arg4,
                       PVOID arg5, PVOID arg6, PVOID arg7, PVOID arg8);
NTSTATUS call_syscall11(PVOID arg1, PVOID arg2, PVOID arg3, PVOID arg4,
                        PVOID arg5, PVOID arg6, PVOID arg7, PVOID arg8,
                        PVOID arg9, PVOID arg10, PVOID arg11);

#ifdef __cplusplus
}
#endif
