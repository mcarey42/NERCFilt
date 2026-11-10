// dllmain.cpp - DLL entry point.
//
// Part of NERCFilt.  SPDX-License-Identifier: MIT

#include "Platform.h"

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved) {
  UNREFERENCED_PARAMETER(reserved);
  if (reason == DLL_PROCESS_ATTACH)
    DisableThreadLibraryCalls(module); // LSASS has many threads; we need none
  return TRUE;
}
