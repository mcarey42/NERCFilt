/*
NERCfilt.cpp - this is a part of the NERCfilt strong password criteria 
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


#include "stdafx.h"
#include <string>
#include <list>
//include <string.h>
#include <Windows.h>
#include <Ntsecapi.h>
#include <WinBase.h>
#include "NERCFilt.h"
#include "RegHelper.h"

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS (0)
#endif

#define MYFILTERNAME "NERCFilt"

extern "C" {

NERCFILT_API BOOLEAN InitializeChangeNotify(void)
{
	return TRUE;
}

NERCFILT_API BOOLEAN PasswordFilter(
  _In_  PUNICODE_STRING AccountName,
  _In_  PUNICODE_STRING FullName,
  _In_  PUNICODE_STRING Password,
  _In_  BOOLEAN SetOperation
)
{
	bool has_caps = false;
	bool has_lower = false;
	bool has_num = false;
	bool has_special = false;

	// GetStringTypeEx result.
	BOOL type_check_ok = FALSE;

	// String check index.
	int idx = 0;

	// We allow administrators to set the password and ignore their own filters.
	if (SetOperation == TRUE)
		return TRUE;

	// Otherwise, we must meet the criteria.
	if (Password != NULL && Password->Length > 0)
	{
		LPWORD typeBuffer = new WORD[Password->Length];

		// Verify the length is at minimum the number of characters
		if (Password->Length < 10)
			return FALSE;


		type_check_ok = GetStringTypeEx(
			LOCALE_SYSTEM_DEFAULT,
			CT_CTYPE1,
			(LPCTSTR) Password->Buffer,
			Password->Length,
			typeBuffer
			);

		// Fail closed.
		if (type_check_ok == 0)
		{
			delete typeBuffer;
			return FALSE;
		}

		// Verify that there is at least 1 upper case character
		for (idx = 0; idx < Password->Length; idx++)
		{
			if (typeBuffer[idx] & C1_UPPER)
			{
				has_caps = true;
				break;
			}
		}

		// Verify that there is at least 1 lower case character
		for (idx = 0; idx < Password->Length; idx++)
		{
			if (typeBuffer[idx] & C1_LOWER)
			{
				has_lower = true;
				break;
			}
		}

		// Verify that there is a number character
		for (idx = 0; idx < Password->Length; idx++)
		{
			if (typeBuffer[idx] & C1_DIGIT)
			{
				has_num = true;
				break;
			}
		}

		// Verify that there is a special character.
		for (idx = 0; idx < Password->Length; idx++)
		{
			if (typeBuffer[idx] & C1_PUNCT)
			{
				has_special = true;
				break;
			}
		}

		// Clear the memory once we're done with it.
		//PVOID SecureZeroMemory(
		//_In_  PVOID ptr,
		//_In_  SIZE_T cnt
		//);
		SecureZeroMemory(
			(PVOID) typeBuffer,
			(SIZE_T) (sizeof(WORD) * Password->Length)
			);

		delete typeBuffer;

		if (has_caps && has_lower && has_num && has_special)
			return TRUE;
		else
			return FALSE;
	}
	return FALSE;
}

NERCFILT_API NTSTATUS PasswordChangeNotify(
  _In_  PUNICODE_STRING UserName,
  _In_  ULONG RelativeId,
  _In_  PUNICODE_STRING NewPassword
)
{
	return STATUS_SUCCESS;
}

/*
HKEY_LOCAL_MACHINE
   SYSTEM
      CurrentControlSet
         Control
            Lsa
*/

NERCFILT_API HRESULT __stdcall DllRegisterServer(void)
{
	RegHelper *helper = new RegHelper(TEXT("SYSTEM\\CurrentControlSet\\Control\\Lsa"), HKEY_LOCAL_MACHINE);
	DWORD value_len = 0;
	wchar_t *current_list = helper->value(TEXT("Notification Packages"), &value_len);
	wstring newstring(TEXT("")); 

	list<wstring> *strings = new list<wstring>();

	if (strings == NULL)	return S_FALSE;

	// Look through the double null terminated string list.
	for (wchar_t *iter = current_list; *iter; iter += wcslen(iter) + 1)
	{
		if ( wcslen(iter) >= wcslen( TEXT(MYFILTERNAME) ) )
		{
			if ( wcsncmp( iter, TEXT( MYFILTERNAME ), wcslen( TEXT(MYFILTERNAME) ) ) == 0)
			{
				delete current_list;
				delete strings;
				return S_OK;	// Already there.
			}
		}
		// Otherwise add the string to our list.
		strings->push_back( wstring(iter) );
	}

	// prepend our filter.
	strings->push_front( TEXT(MYFILTERNAME) );

	// build the new buffer.
	size_t buf_len = 0;

	for(list<wstring>::iterator it=strings->begin(); it != strings->end(); it++)
	{
		buf_len += it->length();
		buf_len += 1;	// room for the list ending nulls.
	}
	buf_len += 1;	// room for the list ending nulls.

	wchar_t *output = new wchar_t[buf_len];
	memset( (void *)output, 0, buf_len * sizeof(wchar_t) );

	if (output == NULL)	
	{
		delete current_list;
		delete strings;
		return S_FALSE;
	}

	size_t cur_ptr = 0;
	for(list<wstring>::iterator itr=strings->begin(); itr != strings->end(); itr++)
	{
		wcscpy_s( output + cur_ptr, itr->length() + 1, itr->c_str() );
		output[cur_ptr + itr->length()] = '\0';
		cur_ptr += itr->length() + 1;
	}

	// Build the trailing null set in UNICODE.
	output[cur_ptr] = '\0';

	if ( helper->setValue( TEXT("Notification Packages"), output, (DWORD) buf_len * sizeof(wchar_t) ) == false )
	{
		delete current_list;
		delete strings;
		delete output;
		return S_FALSE;
	}
	else
	{
		delete current_list;
		delete strings;
		delete output;
		return S_OK;
	}

}

NERCFILT_API HRESULT __stdcall DllUnregisterServer(void)
{
	RegHelper *helper = new RegHelper(TEXT("SYSTEM\\CurrentControlSet\\Control\\Lsa"), HKEY_LOCAL_MACHINE);
	DWORD value_len = 0;
	wchar_t *current_list = helper->value(TEXT("Notification Packages"), &value_len);
	wstring newstring(TEXT("")); 

	list<wstring> *strings = new list<wstring>();

	if (strings == NULL)	return S_FALSE;

	// Look through the double null terminated string list.
	for (wchar_t *iter = current_list; *iter; iter += wcslen(iter) + 1)
	{
		if ( wcslen(iter) >= wcslen( TEXT(MYFILTERNAME) ) )
		{
			if ( wcsncmp( iter, TEXT( MYFILTERNAME ), wcslen( TEXT(MYFILTERNAME) ) ) != 0)
			{
				// not out name, we want this one in the output list
				strings->push_back( wstring(iter) );
			}
		}
		else
		{
			// Otherwise add the string to our list.
			strings->push_back( wstring(iter) );
		}
	}

	// build the new buffer.
	size_t buf_len = 0;

	for(list<wstring>::iterator it=strings->begin(); it != strings->end(); it++)
	{
		buf_len += it->length();
		buf_len += 1;	// room for the list ending nulls.
	}
	buf_len += 1;	// room for the list ending nulls.

	wchar_t *output = new wchar_t[buf_len];
	memset( (void *)output, 0, buf_len * sizeof(wchar_t) );

	if (output == NULL)	
	{
		delete current_list;
		delete strings;
		return S_FALSE;
	}

	size_t cur_ptr = 0;
	for(list<wstring>::iterator itr=strings->begin(); itr != strings->end(); itr++)
	{
		wcscpy_s( output + cur_ptr, itr->length() + 1, itr->c_str() );
		output[cur_ptr + itr->length()] = '\0';
		cur_ptr += itr->length() + 1;
	}

	// Build the trailing null set in UNICODE.
	output[cur_ptr] = '\0';

	if ( helper->setValue( TEXT("Notification Packages"), output, (DWORD) buf_len * sizeof(wchar_t) ) == false )
	{
		delete current_list;
		delete strings;
		delete output;
		return S_FALSE;
	}
	else
	{
		delete current_list;
		delete strings;
		delete output;
		return S_OK;
	}

}


}


