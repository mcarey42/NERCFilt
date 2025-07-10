/*
RegHelper.cpp - this is a part of the NERCfilt strong password criteria 
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

#include "StdAfx.h"
#include <windows.h>
#include <string.h>
#include <iostream>
#include "RegHelper.h"

using namespace std;

RegHelper::RegHelper(wchar_t *Path, HKEY hk_local = HKEY_LOCAL_MACHINE){
  DWORD dwDisp;

  if(RegCreateKeyEx(hk_local,
		Path,
		0,
		NULL,
		REG_OPTION_NON_VOLATILE,
		KEY_WRITE|KEY_EXECUTE,
		NULL,
		&m_hkey,
		&dwDisp))
  {
    throw exception("Failed to create key handle");
  }
}

RegHelper::~RegHelper(){
  RegCloseKey(m_hkey);
}

bool RegHelper::setValue(wchar_t *key, wchar_t *value, DWORD value_length){
	if(RegSetValueEx(m_hkey,
		key,
		0,
		REG_MULTI_SZ,
		(BYTE*) value,
		value_length))
	{
		return false;
	} else {
		return true;
	}
}

wchar_t *RegHelper::value(wchar_t *key, DWORD *value_len){
    DWORD BufferSize = 1024;
	wchar_t *buffer = new wchar_t[BufferSize/sizeof(wchar_t)];
    DWORD dwType = 0;
    DWORD dwRet;

    dwType = REG_EXPAND_SZ;
    dwRet = RegQueryValueEx( m_hkey,
                             key,
                             0,
                             &dwType,
                             (LPBYTE)buffer,
                             &BufferSize );
    if( dwRet == ERROR_SUCCESS ){
		*value_len = BufferSize;
		return buffer;
    } else {
		return NULL;
    }
    
}