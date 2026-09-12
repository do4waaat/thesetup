#include "pe_peb_parser.hpp"
#include <cstdio>

int main() {
  VX_TABLE vx = {0};

  PVOID ntdll = get_ntdll();
  if (!ntdll) {
    printf("[-] ntdll not found\n");
    return 1;
  }
  printf("[+] ntdll base: %p\n", ntdll);

  parse_exports(ntdll, &vx);

  printf("NtAllocateVirtualMemory SSN: 0x%X\n",
         vx.NtAllocateVirtualMemory.wSystemCall);
  printf("NtProtectVirtualMemory SSN:  0x%X\n",
         vx.NtProtectVirtualMemory.wSystemCall);
  printf("NtCreateThreadEx SSN:        0x%X\n",
         vx.NtCreateThreadEx.wSystemCall);
  printf("NtWaitForSingleObject SSN:   0x%X\n",
         vx.NtWaitForSingleObject.wSystemCall);

  return 0;
}
