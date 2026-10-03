#include "pe_peb_parser.hpp"
#include <cstring>
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

PVOID get_base(const wchar_t *module_name) {
#if defined(_WIN64)
  PPEB peb = (PPEB)__readgsqword(0x60);
#else
  PPEB peb = (PPEB)__readfsdword(0x30);
#endif
  PPEB_LDR_DATA ldr = (PPEB_LDR_DATA)peb->Ldr;
  PLIST_ENTRY head = &ldr->InMemoryOrderModuleList;
  PLIST_ENTRY current = head->Flink;
  while (head != current) {
    PLDR_DATA_TABLE_ENTRY entry =
        CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    if (wcsstr(entry->FullDllName.Buffer, module_name)) {
      return entry->DllBase;
    }
    current = current->Flink;
  }
  return nullptr;
}

bool resolve_syscall_entry(PVOID nt_base, const char *func_name,
                           PVX_TABLE_ENTRY entry) {
  if (!nt_base || !func_name || !entry)
    return false;

  entry->name = func_name;
  entry->pAddress = nullptr;
  entry->wSystemCall = 0;
  entry->resolved = false;

  PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)nt_base;
  PIMAGE_NT_HEADERS nt_headers =
      (PIMAGE_NT_HEADERS)((PBYTE)nt_base + dos_header->e_lfanew);
  DWORD export_rva =
      nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
          .VirtualAddress;

  if (export_rva == 0)
    return false;

  PIMAGE_EXPORT_DIRECTORY export_dir =
      (PIMAGE_EXPORT_DIRECTORY)((PBYTE)nt_base + export_rva);
  PDWORD names_array = (PDWORD)((PBYTE)nt_base + export_dir->AddressOfNames);
  PWORD ordinals_array =
      (PWORD)((PBYTE)nt_base + export_dir->AddressOfNameOrdinals);
  PDWORD functions_array =
      (PDWORD)((PBYTE)nt_base + export_dir->AddressOfFunctions);

  for (DWORD i = 0; i < export_dir->NumberOfNames; i++) {
    PCHAR current_name = (PCHAR)((PBYTE)nt_base + names_array[i]);

    if (strcmp(current_name, func_name) == 0) {
      WORD ordinal = ordinals_array[i];
      DWORD func_rva = functions_array[ordinal];
      PBYTE func_addr = (PBYTE)nt_base + func_rva;

      WORD syscall_num = 0;
      PBYTE syscall_addr = nullptr;

      for (int j = 0; j < 32; j++) {
        if (func_addr[j] == 0xB8) {
          syscall_num = *(DWORD *)(func_addr + j + 1);
        }
        if (func_addr[j] == 0x0F && func_addr[j + 1] == 0x05) {
          syscall_addr = func_addr + j;
          break;
        }
      }

      entry->pAddress = syscall_addr;
      entry->wSystemCall = syscall_num;
      entry->resolved = (syscall_addr != nullptr && syscall_num != 0);
      return entry->resolved;
    }
  }
  return false;
}

bool parse_exports(PVOID nt_base, const char **func_names, size_t count,
                   std::vector<VX_TABLE_ENTRY> &out_table) {
  if (!nt_base || !func_names || count == 0)
    return false;

  out_table.clear();
  out_table.reserve(count);

  bool all_resolved = true;
  for (size_t i = 0; i < count; i++) {
    VX_TABLE_ENTRY entry;
    if (resolve_syscall_entry(nt_base, func_names[i], &entry)) {
      out_table.push_back(entry);
    } else {
      entry.name = func_names[i];
      entry.pAddress = nullptr;
      entry.wSystemCall = 0;
      entry.resolved = false;
      out_table.push_back(entry);
      all_resolved = false;
    }
  }
  return all_resolved;
}
