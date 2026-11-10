// PasswordPolicy.cpp - password rule evaluation.
//
// This code runs inside LSASS.  It must not throw, must not allocate, and
// must never read past the length it was given: a fault here takes down the
// security subsystem (and reboots a domain controller).
//
// Part of NERCFilt.  SPDX-License-Identifier: MIT

#include "PasswordPolicy.h"

namespace nercfilt {

namespace {

constexpr unsigned kUpper = 1u << 0;
constexpr unsigned kLower = 1u << 1;
constexpr unsigned kDigit = 1u << 2;
constexpr unsigned kSymbol = 1u << 3;

unsigned CountBits(unsigned v) noexcept {
  unsigned n = 0;
  for (; v; v &= v - 1)
    ++n;
  return n;
}

bool ReadDword(const wchar_t *name, unsigned long *out) noexcept {
  DWORD value = 0;
  DWORD size = sizeof(value);
  // RRF_RT_REG_DWORD: a value of any other type is reported as an error and
  // therefore ignored.
  if (RegGetValueW(HKEY_LOCAL_MACHINE, kPolicyKey, name, RRF_RT_REG_DWORD,
                   nullptr, &value, &size) != ERROR_SUCCESS)
    return false;
  *out = value;
  return true;
}

} // namespace

Policy MakePolicy(unsigned long requestedLength,
                  unsigned long requestedClasses) noexcept {
  Policy p;
  p.minimumLength = requestedLength < kCipMinimumLength ? kCipMinimumLength
                    : requestedLength > kMaximumLength  ? kMaximumLength
                                                        : requestedLength;
  p.minimumClasses = requestedClasses < kCipMinimumClasses ? kCipMinimumClasses
                     : requestedClasses > kCharacterClasses
                         ? kCharacterClasses
                         : requestedClasses;
  return p;
}

Policy LoadPolicy() noexcept {
  unsigned long length = kCipMinimumLength;
  unsigned long classes = kCipMinimumClasses;
  ReadDword(kMinimumLengthValue, &length);
  ReadDword(kMinimumClassesValue, &classes);
  return MakePolicy(length, classes);
}

bool MeetsPolicy(const wchar_t *password, std::size_t cch,
                 const Policy &policy) noexcept {
  if (password == nullptr || cch < policy.minimumLength)
    return false;

  // Classify in fixed-size chunks on the stack: no heap allocation inside
  // LSASS, and GetStringTypeW reports one type word per UTF-16 code unit, so
  // chunk boundaries cannot change the result.
  constexpr std::size_t kChunk = 64;
  WORD types[kChunk];
  unsigned seen = 0;
  bool ok = true;

  for (std::size_t offset = 0; offset < cch; offset += kChunk) {
    const std::size_t n = (cch - offset < kChunk) ? cch - offset : kChunk;
    if (!GetStringTypeW(CT_CTYPE1, password + offset, static_cast<int>(n),
                        types)) {
      ok = false; // fail closed
      break;
    }
    for (std::size_t i = 0; i < n; ++i) {
      const WORD t = types[i];
      if (t & C1_UPPER)
        seen |= kUpper;
      if (t & C1_LOWER)
        seen |= kLower;
      if (t & C1_DIGIT)
        seen |= kDigit;
      if (t & C1_PUNCT)
        seen |= kSymbol;
    }
  }

  // The type words reveal the shape of the password; scrub them.
  SecureZeroMemory(types, sizeof(types));

  return ok && CountBits(seen) >= policy.minimumClasses;
}

bool IsExemptAccount(const wchar_t *name, std::size_t cch) noexcept {
  return name != nullptr && cch >= 2 && name[cch - 1] == L'$';
}

} // namespace nercfilt
