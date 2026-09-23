#include <windows.h>
#pragma once
#define AMSI_RESULT_CLEAN 0
#define AMSI_RESULT_DETECTED 32768
typedef HRESULT(WINAPI *fnamsiscanbuffer)(HANDLE, PVOID, ULONG, LPCWSTR, HANDLE,
                                          PVOID);

typedef HRESULT(WINAPI *fnamsiscanstring)(HANDLE, LPCWSTR, LPCWSTR, HANDLE,
                                          PVOID);
