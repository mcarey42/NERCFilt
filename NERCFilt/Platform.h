// Platform.h - Windows headers in the order needed to get both the Win32 API
// and the NTSTATUS codes without macro redefinition warnings.
//
// Part of NERCFilt.  SPDX-License-Identifier: MIT

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <ntsecapi.h>
