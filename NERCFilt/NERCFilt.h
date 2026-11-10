// NERCFilt.h - exported entry points of the NERCFilt password filter.
//
// LSA loads NERCFilt.dll because "NERCFilt" is listed in
// HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages, and calls
// the three password-filter routines below.  DllRegisterServer and
// DllUnregisterServer add and remove that list entry (regsvr32).
//
// Export names come from NERCFilt.def, so they are undecorated on every
// architecture.
//
// Part of NERCFilt.  SPDX-License-Identifier: MIT

#pragma once

#include "Platform.h"

extern "C" {

BOOLEAN NTAPI InitializeChangeNotify(void);

BOOLEAN NTAPI PasswordFilter(_In_opt_ PUNICODE_STRING AccountName,
                             _In_opt_ PUNICODE_STRING FullName,
                             _In_opt_ PUNICODE_STRING Password,
                             _In_ BOOLEAN SetOperation);

NTSTATUS NTAPI PasswordChangeNotify(_In_opt_ PUNICODE_STRING UserName,
                                    _In_ ULONG RelativeId,
                                    _In_opt_ PUNICODE_STRING NewPassword);

HRESULT STDAPICALLTYPE DllRegisterServer(void);
HRESULT STDAPICALLTYPE DllUnregisterServer(void);

} // extern "C"
