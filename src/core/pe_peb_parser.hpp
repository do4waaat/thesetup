#pragma once
#include <windows.h>

typedef struct _VX_TABLE_ENTRY {
  PVOID pAddress;
  DWORD64 dwHash;
  WORD wSystemCall;
} VX_TABLE_ENTRY, *PVX_TABLE_ENTRY;

typedef struct _VX_TABLE {
  VX_TABLE_ENTRY NtAllocateVirtualMemory;
  VX_TABLE_ENTRY NtProtectVirtualMemory;
  VX_TABLE_ENTRY NtCreateThreadEx;
  VX_TABLE_ENTRY NtWaitForSingleObject;
} VX_TABLE, *PVX_TABLE;

PVOID get_ntdll();
VOID parse_exports(PVOID, PVX_TABLE);
