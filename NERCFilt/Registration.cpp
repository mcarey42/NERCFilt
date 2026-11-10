// Registration.cpp - DllRegisterServer / DllUnregisterServer.
//
// `regsvr32 NERCFilt.dll` adds "NERCFilt" to the REG_MULTI_SZ value
//   HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages
// and `regsvr32 /u NERCFilt.dll` removes it.  LSA reads that list at boot, so
// either change takes effect after a restart.
//
// This runs in regsvr32 (not LSASS), but it edits a list that controls what
// LSASS loads, so it is careful to: preserve every other entry and their
// order, match names exactly (case-insensitively, as Windows resolves DLL
// names), refuse to rewrite a value that is not REG_MULTI_SZ, and report
// failures as failing HRESULTs (regsvr32 treats S_FALSE as success).
//
// Part of NERCFilt.  SPDX-License-Identifier: MIT

#include "NERCFilt.h"

#include <algorithm>
#include <new>
#include <string>
#include <vector>

namespace {

constexpr wchar_t kLsaKey[] = L"SYSTEM\\CurrentControlSet\\Control\\Lsa";
constexpr wchar_t kPackagesValue[] = L"Notification Packages";
constexpr wchar_t kPackageName[] = L"NERCFilt";

class RegKey {
public:
  RegKey() = default;
  ~RegKey() {
    if (h_)
      RegCloseKey(h_);
  }
  RegKey(const RegKey &) = delete;
  RegKey &operator=(const RegKey &) = delete;
  HKEY *put() { return &h_; }
  HKEY get() const { return h_; }

private:
  HKEY h_ = nullptr;
};

bool IsOurName(const std::wstring &s) {
  return CompareStringOrdinal(s.c_str(), static_cast<int>(s.size()),
                              kPackageName, -1, TRUE) == CSTR_EQUAL;
}

// Reads the package list.  A missing value is an empty list.
LSTATUS ReadPackages(HKEY key, std::vector<std::wstring> &out) {
  out.clear();
  std::vector<wchar_t> buf;
  // Retry if the value grows between the size query and the read.
  for (int attempt = 0; attempt < 5; ++attempt) {
    DWORD type = 0;
    DWORD size = 0;
    LSTATUS st =
        RegQueryValueExW(key, kPackagesValue, nullptr, &type, nullptr, &size);
    if (st == ERROR_FILE_NOT_FOUND)
      return ERROR_SUCCESS;
    if (st != ERROR_SUCCESS)
      return st;
    if (type != REG_MULTI_SZ)
      return ERROR_INVALID_DATA;

    // Two spare characters guarantee termination even if the stored data
    // is not properly double-NUL terminated.
    buf.assign(size / sizeof(wchar_t) + 2, L'\0');
    DWORD got = size;
    st = RegQueryValueExW(key, kPackagesValue, nullptr, &type,
                          reinterpret_cast<BYTE *>(buf.data()), &got);
    if (st == ERROR_MORE_DATA)
      continue;
    if (st == ERROR_FILE_NOT_FOUND)
      return ERROR_SUCCESS;
    if (st != ERROR_SUCCESS)
      return st;
    if (type != REG_MULTI_SZ)
      return ERROR_INVALID_DATA;

    const std::size_t n = got / sizeof(wchar_t);
    std::size_t i = 0;
    while (i < n) {
      const std::size_t start = i;
      while (i < n && buf[i] != L'\0')
        ++i;
      if (i > start) // skip stray empty entries
        out.emplace_back(buf.data() + start, i - start);
      ++i;
    }
    return ERROR_SUCCESS;
  }
  return ERROR_MORE_DATA;
}

LSTATUS WritePackages(HKEY key, const std::vector<std::wstring> &list) {
  std::vector<wchar_t> data;
  for (const auto &s : list) {
    data.insert(data.end(), s.begin(), s.end());
    data.push_back(L'\0');
  }
  data.push_back(L'\0');
  if (list.empty())
    data.push_back(L'\0');
  return RegSetValueExW(key, kPackagesValue, 0, REG_MULTI_SZ,
                        reinterpret_cast<const BYTE *>(data.data()),
                        static_cast<DWORD>(data.size() * sizeof(wchar_t)));
}

HRESULT UpdateRegistration(bool add) noexcept {
  try {
    RegKey key;
    LSTATUS st = RegOpenKeyExW(HKEY_LOCAL_MACHINE, kLsaKey, 0,
                               KEY_QUERY_VALUE | KEY_SET_VALUE, key.put());
    if (st != ERROR_SUCCESS)
      return HRESULT_FROM_WIN32(static_cast<unsigned long>(st));

    std::vector<std::wstring> list;
    st = ReadPackages(key.get(), list);
    if (st != ERROR_SUCCESS)
      return HRESULT_FROM_WIN32(static_cast<unsigned long>(st));

    bool changed = false;
    if (add) {
      if (std::none_of(list.begin(), list.end(), IsOurName)) {
        list.emplace_back(kPackageName);
        changed = true;
      }
    } else {
      auto end = std::remove_if(list.begin(), list.end(), IsOurName);
      changed = end != list.end();
      list.erase(end, list.end());
    }

    if (changed) {
      st = WritePackages(key.get(), list);
      if (st != ERROR_SUCCESS)
        return HRESULT_FROM_WIN32(static_cast<unsigned long>(st));
    }
    return S_OK;
  } catch (const std::bad_alloc &) {
    return E_OUTOFMEMORY;
  } catch (...) {
    return E_UNEXPECTED;
  }
}

} // namespace

extern "C" {

HRESULT STDAPICALLTYPE DllRegisterServer(void) {
  return UpdateRegistration(true);
}

HRESULT STDAPICALLTYPE DllUnregisterServer(void) {
  return UpdateRegistration(false);
}

} // extern "C"
