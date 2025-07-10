/*
RegHelper.h - this is a part of the NERCfilt strong password criteria 
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

#pragma once
#include <string.h>
#include <windows.h>
using namespace std;

class RegHelper {
  public:
    RegHelper(wchar_t *Path, HKEY hk_local);
    ~RegHelper();
    bool setValue(wchar_t *key, wchar_t *value, DWORD value_length);
    wchar_t *value(wchar_t *key, DWORD *value_len);
  private:
    HKEY m_hkey;
};