#include "../../core/asm/asm_functions.h"
#include "../../core/pe_peb_parser.hpp"
#include <cstdint>
#include <libloaderapi.h>
#include <minwindef.h>
#include <vector>
#include <windef.h>
#include <windows.h>
#include <winnt.h>
#include <winternl.h>

PVOID g_SyscallAddress = NULL;
DWORD g_SyscallNumber = 0;

void SetSyscall(const VX_TABLE_ENTRY &entry) {
  g_SyscallAddress = entry.pAddress;
  g_SyscallNumber = entry.wSystemCall;
}
ULONG GetPageProtection(DWORD characteristics) {
  bool canExecute = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
  bool canRead = (characteristics & IMAGE_SCN_MEM_READ) != 0;
  bool canWrite = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;
  if (canExecute && canRead && canWrite)
    return PAGE_EXECUTE_READWRITE;
  if (canExecute && canRead)
    return PAGE_EXECUTE_READ;
  if (canRead && canWrite)
    return PAGE_READWRITE;
  if (canRead)
    return PAGE_READONLY;
  if (canExecute)
    return PAGE_EXECUTE;
  return PAGE_NOACCESS;
}

bool InitializeSyscalls(std::vector<VX_TABLE_ENTRY> &syscalls) {
  const char *names[] = {"NtAllocateVirtualMemory", "NtWriteVirtualMemory",
                         "NtReadFile", "NtCreateFile", "NtProtecVirtualMemory"};

  PVOID ntdllBase = get_base(L"ntdll.dll");
  if (!ntdllBase) {
    return false;
  }

  if (!parse_exports(ntdllBase, names, 4, syscalls)) {
    return false;
  }
  return true;
}

bool ReadTargetFile(const wchar_t *dosFilePath,
                    const std::vector<VX_TABLE_ENTRY> &syscalls,
                    std::vector<BYTE> &fileBuffer) {
  UNICODE_STRING filepath;
  RtlInitUnicodeString(&filepath, dosFilePath);

  OBJECT_ATTRIBUTES att;
  InitializeObjectAttributes(&att, &filepath, OBJ_CASE_INSENSITIVE, NULL, NULL);

  IO_STATUS_BLOCK iost = {0};
  HANDLE hFile = NULL;

  SetSyscall(syscalls[3]);
  NTSTATUS status =
      call_syscall11(&hFile, (PVOID)(DWORD64)GENERIC_READ, &att, &iost, NULL,
                     (PVOID)(DWORD64)FILE_ATTRIBUTE_NORMAL,
                     (PVOID)(DWORD64)FILE_SHARE_READ, (PVOID)(DWORD64)FILE_OPEN,
                     (PVOID)(DWORD64)FILE_NON_DIRECTORY_FILE, NULL, NULL);

  if (status != 0 || hFile == NULL) {
    return false;
  }

  LARGE_INTEGER fileSize;
  if (!GetFileSizeEx(hFile, &fileSize)) {
    CloseHandle(hFile);
    return false;
  }

  fileBuffer.resize(fileSize.QuadPart);
  LARGE_INTEGER byteOffset = {0};
  ZeroMemory(&iost, sizeof(iost));

  SetSyscall(syscalls[2]);
  status = call_syscall11(hFile, NULL, NULL, NULL, &iost, fileBuffer.data(),
                          (PVOID)(DWORD64)fileSize.QuadPart, &byteOffset, NULL,
                          NULL, NULL);

  CloseHandle(hFile);

  if (status != 0) {
    return false;
  }

  return true;
}

PVOID AllocateTargetMemory(HANDLE hProcess, SIZE_T imageSize,
                           const std::vector<VX_TABLE_ENTRY> &syscalls) {
  PVOID baseAddress = NULL;
  SIZE_T sizeToAllocate = imageSize;

  SetSyscall(syscalls[0]);
  NTSTATUS status =
      call_syscall8(hProcess, &baseAddress, (PVOID)0, &sizeToAllocate,
                    (PVOID)(DWORD64)(MEM_RESERVE | MEM_COMMIT),
                    (PVOID)(DWORD64)PAGE_READWRITE, NULL, NULL);

  if (status != 0) {
    return nullptr;
  }

  return baseAddress;
}

bool MapImageSections(HANDLE hProcess, PVOID baseAddress,
                      const std::vector<BYTE> &fileBuffer,
                      const std::vector<VX_TABLE_ENTRY> &syscalls) {
  PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)fileBuffer.data();
  PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PBYTE)dos + dos->e_lfanew);
  PIMAGE_FILE_HEADER fileHeader = &nt->FileHeader;
  PIMAGE_OPTIONAL_HEADER optH = &nt->OptionalHeader;

  SIZE_T toWrite = (SIZE_T)optH->SizeOfHeaders;
  SIZE_T written = 0;

  SetSyscall(syscalls[1]);

  NTSTATUS status =
      call_syscall8(hProcess, baseAddress, (PVOID)fileBuffer.data(),
                    (PVOID)toWrite, &written, NULL, NULL, NULL);
  if (status != 0)
    return false;

  WORD sectNum = fileHeader->NumberOfSections;
  PIMAGE_SECTION_HEADER firstSection =
      (PIMAGE_SECTION_HEADER)((PBYTE)optH + fileHeader->SizeOfOptionalHeader);

  for (WORD i = 0; i < sectNum; i++) {
    PIMAGE_SECTION_HEADER currentSection = &firstSection[i];

    if (currentSection->SizeOfRawData == 0)
      continue;

    PVOID remoteSectionAddr =
        (PVOID)((ULONG_PTR)baseAddress + currentSection->VirtualAddress);
    PVOID localSectionRaw = (PVOID)((ULONG_PTR)fileBuffer.data() +
                                    currentSection->PointerToRawData);
    SIZE_T sectionSize = (SIZE_T)currentSection->SizeOfRawData;

    status = call_syscall8(hProcess, remoteSectionAddr, localSectionRaw,
                           (PVOID)sectionSize, &written, NULL, NULL, NULL);
    if (status != 0) {
      return false;
    }
  }

  return true;
}

void ApplyRelocations(PVOID baseAddress, PIMAGE_OPTIONAL_HEADER optH,
                      PIMAGE_DATA_DIRECTORY dataDir) {
  DWORD64 delta = (DWORD64)baseAddress - optH->ImageBase;
  if (delta == 0)
    return;

  PIMAGE_BASE_RELOCATION reloc =
      (PIMAGE_BASE_RELOCATION)((PBYTE)baseAddress +
                               dataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC]
                                   .VirtualAddress);
  DWORD maxRelocSize = dataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
  DWORD processedSize = 0;

  while (processedSize < maxRelocSize && reloc->SizeOfBlock != 0) {
    DWORD entriesCount =
        (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
    PWORD pCluster = (PWORD)((PBYTE)reloc + sizeof(IMAGE_BASE_RELOCATION));

    for (DWORD i = 0; i < entriesCount; i++) {
      WORD record = pCluster[i];
      uint8_t type = (record >> 12) & 0x0F;
      DWORD offset = record & 0xFFF;

      if (type == IMAGE_REL_BASED_DIR64) {
        PDWORD64 patchAddr =
            (PDWORD64)((PBYTE)baseAddress + reloc->VirtualAddress + offset);
        *patchAddr += delta;
      } else if (type == IMAGE_REL_BASED_HIGHLOW) {
        PDWORD patchAddr =
            (PDWORD)((PBYTE)baseAddress + reloc->VirtualAddress + offset);
        *patchAddr += (DWORD)delta;
      }
    }
    processedSize += reloc->SizeOfBlock;
    reloc = (PIMAGE_BASE_RELOCATION)((PBYTE)reloc + reloc->SizeOfBlock);
  }
}
bool change_protect(HANDLE hProcess, PVOID baseAddress, PIMAGE_DOS_HEADER dos,
                    const std::vector<VX_TABLE_ENTRY> &syscalls) {
  PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PBYTE)dos + dos->e_lfanew);
  PIMAGE_FILE_HEADER fileHeader = &nt->FileHeader;
  PIMAGE_OPTIONAL_HEADER optH = &nt->OptionalHeader;
  SIZE_T toWrite = (SIZE_T)optH->SizeOfHeaders;
  SIZE_T written = 0;

  WORD sectNum = fileHeader->NumberOfSections;
  PIMAGE_SECTION_HEADER firstSection =
      (PIMAGE_SECTION_HEADER)((PBYTE)optH + fileHeader->SizeOfOptionalHeader);
  SetSyscall(syscalls[4]);
  for (WORD i = 0; i < sectNum; i++) {
    PIMAGE_SECTION_HEADER currentSection = &firstSection[i];
    ULONG oldprotect = 0;
    SIZE_T size = (SIZE_T)(DWORD)currentSection->Misc.VirtualSize;
    PVOID baseaddrptr = (PBYTE)baseAddress + currentSection->VirtualAddress;
    call_syscall8(
        (PVOID)hProcess, &baseaddrptr, (PVOID)&size,
        (PVOID)((ULONG_PTR)GetPageProtection(currentSection->Characteristics)),
        &oldprotect, NULL, NULL, NULL);
  }
  return true;
}

bool resolve_imports(PVOID baseaddr, PIMAGE_DATA_DIRECTORY data) {
  if (data[1].VirtualAddress == 0) {
    return false;
  }
  PIMAGE_IMPORT_DESCRIPTOR imp_des =
      (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)baseaddr + data[1].VirtualAddress);
  while (imp_des->Name != 0) {
    PIMAGE_THUNK_DATA64 ilt =
        (PIMAGE_THUNK_DATA64)((PBYTE)baseaddr + imp_des->OriginalFirstThunk);
    PIMAGE_THUNK_DATA64 iat =
        (PIMAGE_THUNK_DATA64)((PBYTE)baseaddr + imp_des->FirstThunk);
    if (imp_des->OriginalFirstThunk == 0) {
      ilt = iat;
    }
    DWORD dll_rva = imp_des->Name;
    const char *name = (const char *)((PBYTE)baseaddr + imp_des->Name);
    HMODULE hmodule = LoadLibraryA(name);
    if (hmodule == NULL) {
      imp_des++;
      continue;
    }
    while (ilt->u1.AddressOfData != 0) {
      int bit = ((uintptr_t)ilt->u1.Ordinal >> 63) & 1;
      if (bit == 0) {
        PIMAGE_IMPORT_BY_NAME nams =
            (PIMAGE_IMPORT_BY_NAME)((PBYTE)baseaddr + ilt->u1.AddressOfData);
        const char *poka = nams->Name;
        FARPROC ziga = GetProcAddress(hmodule, poka);
        if (ziga == NULL) {
          ilt += 1;
          iat += 1;
          continue;
        }
        iat->u1.Function = (ULONGLONG)ziga;
        ilt += 1;
        iat += 1;
        continue;
      }
      DWORD bits = (DWORD)ilt->u1.Ordinal & 0xFFFF;
      FARPROC ptr = GetProcAddress(hmodule, (LPCSTR)(ULONG_PTR)bits);
      if (ptr == NULL) {
        ilt += 1;
        iat += 1;
        continue;
      }
      iat->u1.Function = (ULONGLONG)ptr;
      ilt += 1;
      iat += 1;
    }
    imp_des += 1;
  }
  return true;
}

bool callentrypoint(PIMAGE_DOS_HEADER dos, PIMAGE_OPTIONAL_HEADER optH,
                    PVOID baseAddress) {

  if (optH->AddressOfEntryPoint == 0) {
    return true;
  }

  typedef BOOL(WINAPI * PDLL_MAIN)(HINSTANCE, DWORD, LPVOID);

  ULONG_PTR realAddress = (ULONG_PTR)baseAddress + optH->AddressOfEntryPoint;
  PDLL_MAIN pDllMain = (PDLL_MAIN)realAddress;

  pDllMain((HINSTANCE)baseAddress, DLL_PROCESS_ATTACH, NULL);

  return true;
}

int main() {
  HANDLE hProcess = (HANDLE)-1;
  std::vector<VX_TABLE_ENTRY> syscallTable;

  if (!InitializeSyscalls(syscallTable)) {
    return -1;
  }

  std::vector<BYTE> fileBuffer;
  const wchar_t *targetPath = L"\\??\\C:\\Windows\\System32\\calc.dll";
  if (!ReadTargetFile(targetPath, syscallTable, fileBuffer)) {
    return -1;
  }

  PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)fileBuffer.data();
  PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PBYTE)dos + dos->e_lfanew);
  PIMAGE_OPTIONAL_HEADER optH = &nt->OptionalHeader;
  PIMAGE_DATA_DIRECTORY dataDir = optH->DataDirectory;

  PVOID baseAddress =
      AllocateTargetMemory(hProcess, optH->SizeOfImage, syscallTable);
  if (!baseAddress) {
    return -1;
  }

  if (!MapImageSections(hProcess, baseAddress, fileBuffer, syscallTable)) {
    return -1;
  }

  if (dataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0) {
    ApplyRelocations(baseAddress, optH, dataDir);
  }

  return 0;
}
