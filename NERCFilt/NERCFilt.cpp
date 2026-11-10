// NERCFilt.cpp - LSA password filter entry points.
//
// NERCFilt enforces the NERC CIP-007-6 R5.5 password parameters (see
// PasswordPolicy.h) for every password change and administrative password
// set processed by this machine's SAM.  Install it on every domain
// controller to cover a domain.
//
// Copyright (c) 2013-2026 Mark G. Carey, Peak Security, Inc.
// SPDX-License-Identifier: MIT

#include "NERCFilt.h"
#include "PasswordPolicy.h"

extern "C" {

BOOLEAN NTAPI InitializeChangeNotify(void) { return TRUE; }

BOOLEAN NTAPI PasswordFilter(_In_opt_ PUNICODE_STRING AccountName,
                             _In_opt_ PUNICODE_STRING FullName,
                             _In_opt_ PUNICODE_STRING Password,
                             _In_ BOOLEAN SetOperation) {
  UNREFERENCED_PARAMETER(FullName);

  // Administrative sets (SetOperation == TRUE) are checked like ordinary
  // changes: CIP R5.5 applies to every password, not only user-chosen ones.
  UNREFERENCED_PARAMETER(SetOperation);

  // UNICODE_STRING lengths are in bytes and the buffers are not terminated.
  if (AccountName != nullptr &&
      nercfilt::IsExemptAccount(AccountName->Buffer,
                                AccountName->Length / sizeof(WCHAR)))
    return TRUE;

  if (Password == nullptr || Password->Buffer == nullptr)
    return FALSE;

  return nercfilt::MeetsPolicy(Password->Buffer,
                               Password->Length / sizeof(WCHAR),
                               nercfilt::LoadPolicy())
             ? TRUE
             : FALSE;
}

NTSTATUS NTAPI PasswordChangeNotify(_In_opt_ PUNICODE_STRING UserName,
                                    _In_ ULONG RelativeId,
                                    _In_opt_ PUNICODE_STRING NewPassword) {
  UNREFERENCED_PARAMETER(UserName);
  UNREFERENCED_PARAMETER(RelativeId);
  UNREFERENCED_PARAMETER(NewPassword);
  return STATUS_SUCCESS;
}

} // extern "C"
