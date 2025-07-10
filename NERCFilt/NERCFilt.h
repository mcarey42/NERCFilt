/*
NERCfilt.h - this is a part of the NERCfilt strong password criteria 
enforcment module.  It's intended purpose is to meet the criteria 
set forth in NERC CIP-007-3 and later, and CIP-005-3 and later.

The enforcement of a capital letter, a lower case letter, a number,
and a special character (symbol) are enforced in the same manner as
the MicroSoft password filter, using the same verification mechanism.

Copyright (C) 2013 Mark G. Carey, Peak Security, Inc.

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifdef NERCFILT_EXPORTS
#define NERCFILT_API __declspec(dllexport)
#else
#define NERCFILT_API __declspec(dllimport)
#endif

extern "C" {

NERCFILT_API BOOLEAN InitializeChangeNotify(void);

NERCFILT_API BOOLEAN PasswordFilter(
  _In_  PUNICODE_STRING AccountName,
  _In_  PUNICODE_STRING FullName,
  _In_  PUNICODE_STRING Password,
  _In_  BOOLEAN SetOperation
);

NERCFILT_API NTSTATUS PasswordChangeNotify(
  _In_  PUNICODE_STRING UserName,
  _In_  ULONG RelativeId,
  _In_  PUNICODE_STRING NewPassword
);

NERCFILT_API HRESULT __stdcall DllUnregisterServer(void);
NERCFILT_API HRESULT __stdcall DllRegisterServer(void);
}