#include <windows.h>
#pragma once // Защита от повторного включения файла

#ifdef __cplusplus
extern "C" {
#endif

// ---- Пиши сюда все свои функции из ассемблера списком ----

DWORD64 find_rsp();
DWORD64 find_rbp();
DWORD64 find_rip();
NTSTATUS call_syscall(PVOID, DWORD, PVOID, PVOID);
#ifdef __cplusplus
}
#endif
