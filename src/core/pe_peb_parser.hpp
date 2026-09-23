#pragma once
#include <vector>
#include <windows.h>

typedef struct _VX_TABLE_ENTRY {
  const char *name;
  PVOID pAddress;
  DWORD wSystemCall;
  bool resolved;
} VX_TABLE_ENTRY, *PVX_TABLE_ENTRY;

PVOID get_base(const wchar_t *module_name);

bool resolve_syscall_entry(PVOID nt_base, const char *func_name,
                           PVX_TABLE_ENTRY entry);

bool parse_exports(PVOID nt_base, const char **func_names, size_t count,
                   std::vector<VX_TABLE_ENTRY> &out_table);
