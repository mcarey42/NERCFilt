/*
NERCFiltTests.cpp - black-box tests for NERCFilt.dll.

The DLL is loaded exactly as LSA loads it (LoadLibrary + GetProcAddress on the
undecorated export names) and each test case runs in its own child process, so
an access violation or stack corruption inside the filter is reported as a
failed test instead of killing the whole run.

Every password handed to PasswordFilter is placed so that it ends exactly at a
PAGE_NOACCESS guard page and carries no NUL terminator.  Any read past
UNICODE_STRING.Length therefore faults immediately.

Usage:
  NERCFiltTests.exe               run the policy tests (no system changes)
  NERCFiltTests.exe --registry    also run tests that modify HKLM (LSA
                                  "Notification Packages" and the NERCFilt
                                  policy key).  Original values are restored
                                  afterwards.  Intended for disposable CI
                                  machines; requires elevation.
  NERCFiltTests.exe --list        list test cases
  NERCFiltTests.exe --case NAME   run one case in-process (used internally)

Environment:
  NERCFILT_DLL   path to the DLL under test (default: NERCFilt.dll next to
                 this executable)

SPDX-License-Identifier: MIT
*/

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <ntsecapi.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <string>
#include <vector>

namespace {

// ---------------------------------------------------------------------------
// Minimal test framework
// ---------------------------------------------------------------------------

int g_failures = 0;

#define CHECK(cond)                                                            \
  do {                                                                         \
    if (!(cond)) {                                                             \
      std::printf("    CHECK FAILED %s:%d: %s\n", __FILE__, __LINE__, #cond);  \
      ++g_failures;                                                            \
    }                                                                          \
  } while (0)

#define CHECK_MSG(cond, ...)                                                   \
  do {                                                                         \
    if (!(cond)) {                                                             \
      std::printf("    CHECK FAILED %s:%d: %s -- ", __FILE__, __LINE__, #cond); \
      std::printf(__VA_ARGS__);                                                \
      std::printf("\n");                                                       \
      ++g_failures;                                                            \
    }                                                                          \
  } while (0)

struct TestCase {
  const char *name;
  void (*fn)();
  bool needs_registry;
};

std::vector<TestCase> &Registry() {
  static std::vector<TestCase> cases;
  return cases;
}

struct Registrar {
  Registrar(const char *name, void (*fn)(), bool reg) {
    Registry().push_back({name, fn, reg});
  }
};

#define TEST(name)                                                             \
  void name();                                                                 \
  Registrar name##_registrar(#name, name, false);                              \
  void name()

#define REGISTRY_TEST(name)                                                    \
  void name();                                                                 \
  Registrar name##_registrar(#name, name, true);                               \
  void name()

// ---------------------------------------------------------------------------
// DLL under test
// ---------------------------------------------------------------------------

using InitializeChangeNotifyFn = BOOLEAN(NTAPI *)(void);
using PasswordFilterFn = BOOLEAN(NTAPI *)(PUNICODE_STRING, PUNICODE_STRING,
                                          PUNICODE_STRING, BOOLEAN);
using PasswordChangeNotifyFn = NTSTATUS(NTAPI *)(PUNICODE_STRING, ULONG,
                                                 PUNICODE_STRING);
using DllServerFn = HRESULT(STDAPICALLTYPE *)(void);

std::wstring DllPath() {
  wchar_t env[MAX_PATH * 2];
  DWORD n = GetEnvironmentVariableW(L"NERCFILT_DLL", env, MAX_PATH * 2);
  if (n > 0 && n < MAX_PATH * 2)
    return env;
  wchar_t self[MAX_PATH * 2];
  n = GetModuleFileNameW(nullptr, self, MAX_PATH * 2);
  std::wstring path(self, n);
  size_t slash = path.find_last_of(L"\\/");
  path = (slash == std::wstring::npos) ? L"" : path.substr(0, slash + 1);
  return path + L"NERCFilt.dll";
}

HMODULE Dll() {
  static HMODULE h = nullptr;
  if (!h) {
    std::wstring path = DllPath();
    h = LoadLibraryExW(path.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (!h) {
      std::printf("    cannot load %ls (error %lu)\n", path.c_str(),
                  GetLastError());
      std::exit(3);
    }
  }
  return h;
}

template <typename T> T Export(const char *name) {
  return reinterpret_cast<T>(
      reinterpret_cast<void *>(GetProcAddress(Dll(), name)));
}

// A UTF-16 string placed so its last code unit is the last thing before a
// PAGE_NOACCESS page.  No terminator is written.
class GuardedString {
public:
  explicit GuardedString(const std::wstring &s) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    page_ = si.dwPageSize;
    size_t bytes = s.size() * sizeof(wchar_t);
    size_t data_pages = (bytes + page_ - 1) / page_;
    if (data_pages == 0)
      data_pages = 1;
    total_ = (data_pages + 1) * page_;
    base_ = static_cast<BYTE *>(
        VirtualAlloc(nullptr, total_, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!base_) {
      std::printf("    VirtualAlloc failed\n");
      std::exit(3);
    }
    BYTE *guard = base_ + data_pages * page_;
    DWORD old;
    VirtualProtect(guard, page_, PAGE_NOACCESS, &old);
    wchar_t *buf = reinterpret_cast<wchar_t *>(guard - bytes);
    if (bytes)
      std::memcpy(buf, s.data(), bytes);
    us_.Buffer = buf;
    us_.Length = static_cast<USHORT>(bytes);
    us_.MaximumLength = static_cast<USHORT>(bytes);
  }
  ~GuardedString() { VirtualFree(base_, 0, MEM_RELEASE); }
  GuardedString(const GuardedString &) = delete;
  GuardedString &operator=(const GuardedString &) = delete;
  PUNICODE_STRING get() { return &us_; }

private:
  BYTE *base_ = nullptr;
  size_t page_ = 0;
  size_t total_ = 0;
  UNICODE_STRING us_{};
};

bool Filter(const std::wstring &account, const std::wstring &password,
            bool set_operation = false) {
  auto fn = Export<PasswordFilterFn>("PasswordFilter");
  if (!fn) {
    std::printf("    PasswordFilter export missing\n");
    std::exit(3);
  }
  GuardedString acct(account);
  GuardedString full(L"Test User");
  GuardedString pw(password);
  return fn(acct.get(), full.get(), pw.get(), set_operation ? TRUE : FALSE) !=
         FALSE;
}

bool Accepts(const std::wstring &pw) { return Filter(L"alice", pw); }

// ---------------------------------------------------------------------------
// Registry helpers
// ---------------------------------------------------------------------------

const wchar_t kLsaKey[] = L"SYSTEM\\CurrentControlSet\\Control\\Lsa";
const wchar_t kPackagesValue[] = L"Notification Packages";
const wchar_t kPolicyKey[] = L"SOFTWARE\\NERCFilt";
const wchar_t kMinLengthValue[] = L"MinimumLength";
const wchar_t kMinClassesValue[] = L"MinimumCharacterClasses";

struct RawValue {
  bool exists = false;
  DWORD type = 0;
  std::vector<BYTE> data;
};

RawValue ReadRaw(const wchar_t *key, const wchar_t *value) {
  RawValue rv;
  HKEY h;
  if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, key, 0, KEY_QUERY_VALUE, &h) !=
      ERROR_SUCCESS)
    return rv;
  DWORD size = 0;
  if (RegQueryValueExW(h, value, nullptr, &rv.type, nullptr, &size) ==
      ERROR_SUCCESS) {
    rv.data.resize(size);
    if (RegQueryValueExW(h, value, nullptr, &rv.type, rv.data.data(), &size) ==
        ERROR_SUCCESS) {
      rv.data.resize(size);
      rv.exists = true;
    }
  }
  RegCloseKey(h);
  return rv;
}

void WriteRaw(const wchar_t *key, const wchar_t *value, const RawValue &rv) {
  HKEY h;
  if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, key, 0, nullptr, 0,
                      KEY_SET_VALUE | KEY_QUERY_VALUE, nullptr, &h,
                      nullptr) != ERROR_SUCCESS) {
    std::printf("    cannot open HKLM\\%ls for writing\n", key);
    std::exit(3);
  }
  if (rv.exists)
    RegSetValueExW(h, value, 0, rv.type, rv.data.data(),
                   static_cast<DWORD>(rv.data.size()));
  else
    RegDeleteValueW(h, value);
  RegCloseKey(h);
}

void SetPackages(const std::vector<std::wstring> &list) {
  RawValue rv;
  rv.exists = true;
  rv.type = REG_MULTI_SZ;
  for (const auto &s : list) {
    const BYTE *p = reinterpret_cast<const BYTE *>(s.c_str());
    rv.data.insert(rv.data.end(), p, p + (s.size() + 1) * sizeof(wchar_t));
  }
  rv.data.push_back(0);
  rv.data.push_back(0);
  WriteRaw(kLsaKey, kPackagesValue, rv);
}

void DeletePackages() { WriteRaw(kLsaKey, kPackagesValue, RawValue{}); }

std::vector<std::wstring> GetPackages() {
  std::vector<std::wstring> out;
  RawValue rv = ReadRaw(kLsaKey, kPackagesValue);
  if (!rv.exists)
    return out;
  const wchar_t *p = reinterpret_cast<const wchar_t *>(rv.data.data());
  size_t n = rv.data.size() / sizeof(wchar_t);
  size_t i = 0;
  while (i < n && p[i]) {
    size_t start = i;
    while (i < n && p[i])
      ++i;
    out.emplace_back(p + start, i - start);
    ++i;
  }
  return out;
}

size_t CountCi(const std::vector<std::wstring> &list, const wchar_t *name) {
  size_t c = 0;
  for (const auto &s : list)
    if (_wcsicmp(s.c_str(), name) == 0)
      ++c;
  return c;
}

void SetPolicyDword(const wchar_t *value, DWORD v) {
  RawValue rv;
  rv.exists = true;
  rv.type = REG_DWORD;
  rv.data.resize(sizeof(DWORD));
  std::memcpy(rv.data.data(), &v, sizeof(DWORD));
  WriteRaw(kPolicyKey, value, rv);
}

void ResetPolicy() {
  WriteRaw(kPolicyKey, kMinLengthValue, RawValue{});
  WriteRaw(kPolicyKey, kMinClassesValue, RawValue{});
}

HRESULT Register() { return Export<DllServerFn>("DllRegisterServer")(); }
HRESULT Unregister() { return Export<DllServerFn>("DllUnregisterServer")(); }

std::vector<std::wstring> ManyPackages() {
  std::vector<std::wstring> list;
  for (int i = 0; i < 80; ++i) {
    wchar_t buf[64];
    std::swprintf(buf, 64, L"ThirdPartyPackage_%02d_padding", i);
    list.push_back(buf);
  }
  return list;
}

// ---------------------------------------------------------------------------
// Export / ABI tests
// ---------------------------------------------------------------------------

TEST(exports_have_undecorated_names) {
  // LSA and regsvr32 look these up by their plain names.
  const char *names[] = {"InitializeChangeNotify", "PasswordFilter",
                         "PasswordChangeNotify", "DllRegisterServer",
                         "DllUnregisterServer"};
  for (const char *n : names)
    CHECK_MSG(GetProcAddress(Dll(), n) != nullptr, "missing export %s", n);
}

TEST(initialize_and_notify_succeed) {
  CHECK(Export<InitializeChangeNotifyFn>("InitializeChangeNotify")() != FALSE);
  GuardedString user(L"alice");
  GuardedString pw(L"Abcdef1!");
  CHECK(Export<PasswordChangeNotifyFn>("PasswordChangeNotify")(
            user.get(), 1001, pw.get()) == STATUS_SUCCESS);
}

// ---------------------------------------------------------------------------
// Length (CIP-007-6 R5.5.1: at least 8 characters by default)
// ---------------------------------------------------------------------------

TEST(length_counts_characters_not_bytes) {
  // 5 characters = 10 bytes.  NERCFilt 1.0 compared the byte count against 10.
  CHECK(!Accepts(L"aA1!b"));
}

TEST(length_seven_rejected) { CHECK(!Accepts(L"Abcde1!")); }

TEST(length_eight_accepted) { CHECK(Accepts(L"Abcdef1!")); }

TEST(length_long_accepted) {
  std::wstring pw(256, L'a');
  pw[100] = L'Q';
  pw[255] = L'7';
  CHECK(Accepts(pw));
}

TEST(classes_found_anywhere_in_long_password) {
  // Class-bearing characters only at awkward offsets in a long password.
  std::wstring pw(1000, L'x');
  pw[64] = L'B';
  pw[513] = L'#';
  CHECK(Accepts(pw));
}

// ---------------------------------------------------------------------------
// Complexity (CIP-007-6 R5.5.2: 3 of 4 classes by default)
// ---------------------------------------------------------------------------

TEST(three_classes_upper_lower_digit) { CHECK(Accepts(L"Abcdefg1")); }
TEST(three_classes_upper_lower_symbol) { CHECK(Accepts(L"Abcdefg!")); }
TEST(three_classes_lower_digit_symbol) { CHECK(Accepts(L"abcdef1!")); }
TEST(three_classes_upper_digit_symbol) { CHECK(Accepts(L"ABCDEF1!")); }
TEST(four_classes) { CHECK(Accepts(L"Abcdef1!")); }

TEST(two_classes_rejected) {
  CHECK(!Accepts(L"abcdefgh1"));
  CHECK(!Accepts(L"Abcdefghi"));
  CHECK(!Accepts(L"abcdefgh!"));
  CHECK(!Accepts(L"12345678!"));
}

TEST(one_class_rejected) {
  CHECK(!Accepts(L"abcdefghijkl"));
  CHECK(!Accepts(L"123456789012"));
}

TEST(space_is_not_a_symbol) { CHECK(!Accepts(L"abcd efgh1")); }

TEST(non_ascii_letters_classified) {
  // U+00DC (upper), lower-case accented letters, digit.
  CHECK(Accepts(L"Ünïcödé1"));
}

// ---------------------------------------------------------------------------
// Robustness: never read beyond UNICODE_STRING.Length
// ---------------------------------------------------------------------------

TEST(ignores_data_after_length) {
  // Only "abcdefgh" is inside Length.  The characters after it would satisfy
  // the policy if the filter read past the end.
  std::wstring storage = L"abcdefghA1!A1!A1!";
  UNICODE_STRING pw;
  pw.Buffer = &storage[0];
  pw.Length = 8 * sizeof(wchar_t);
  pw.MaximumLength = static_cast<USHORT>(storage.size() * sizeof(wchar_t));
  GuardedString acct(L"alice");
  GuardedString full(L"Alice");
  CHECK(Export<PasswordFilterFn>("PasswordFilter")(acct.get(), full.get(), &pw,
                                                    FALSE) == FALSE);
}

TEST(odd_byte_length_truncates) {
  // 17 bytes: 8 whole characters plus a stray byte.  The stray byte lies in
  // the guard page, so it must be ignored (and never touched).
  GuardedString acct(L"alice");
  GuardedString full(L"Alice");
  GuardedString pw(L"Abcdef1!");
  pw.get()->Length = 17;
  pw.get()->MaximumLength = 17;
  CHECK(Export<PasswordFilterFn>("PasswordFilter")(acct.get(), full.get(),
                                                    pw.get(), FALSE) != FALSE);
}

TEST(null_and_empty_inputs_rejected_without_crash) {
  auto fn = Export<PasswordFilterFn>("PasswordFilter");
  GuardedString acct(L"alice");
  GuardedString full(L"Alice");
  CHECK(fn(acct.get(), full.get(), nullptr, FALSE) == FALSE);

  UNICODE_STRING empty{0, 0, nullptr};
  CHECK(fn(acct.get(), full.get(), &empty, FALSE) == FALSE);

  UNICODE_STRING bogus{16, 16, nullptr};
  CHECK(fn(acct.get(), full.get(), &bogus, FALSE) == FALSE);

  GuardedString pw(L"Abcdef1!");
  CHECK(fn(nullptr, nullptr, pw.get(), FALSE) != FALSE);
}

// ---------------------------------------------------------------------------
// Administrative password sets
// ---------------------------------------------------------------------------

TEST(admin_set_weak_password_rejected) {
  CHECK(!Filter(L"alice", L"password", true));
  CHECK(!Filter(L"alice", L"aA1!", true));
}

TEST(admin_set_compliant_password_accepted) {
  CHECK(Filter(L"alice", L"Abcdefg1", true));
}

TEST(machine_and_trust_accounts_exempt) {
  // Computer, trust and gMSA account names end in '$'; their passwords are
  // generated by the system and must never be blocked.
  CHECK(Filter(L"WS01$", L"x", true));
  CHECK(Filter(L"WS01$", L"x", false));
  CHECK(Filter(L"CONTOSO$", L"一二三", true));
}

TEST(dollar_elsewhere_not_exempt) {
  CHECK(!Filter(L"al$ce", L"weak", true));
  CHECK(!Filter(L"$", L"weak", false));
}

// ---------------------------------------------------------------------------
// Registration (modifies HKLM; --registry only)
// ---------------------------------------------------------------------------

REGISTRY_TEST(reg_register_adds_once) {
  SetPackages({L"scecli", L"rassfm"});
  CHECK(Register() == S_OK);
  auto l = GetPackages();
  CHECK(CountCi(l, L"NERCFilt") == 1);
  CHECK(CountCi(l, L"scecli") == 1);
  CHECK(CountCi(l, L"rassfm") == 1);
  CHECK(Register() == S_OK);
  CHECK(CountCi(GetPackages(), L"NERCFilt") == 1);
  CHECK(GetPackages().size() == 3);
}

REGISTRY_TEST(reg_register_when_value_missing) {
  DeletePackages();
  CHECK(Register() == S_OK);
  auto l = GetPackages();
  CHECK(l.size() == 1);
  CHECK(CountCi(l, L"NERCFilt") == 1);
}

REGISTRY_TEST(reg_register_large_list) {
  auto many = ManyPackages(); // ~4 KB, well past NERCFilt 1.0's 1 KB buffer
  SetPackages(many);
  CHECK(Register() == S_OK);
  auto l = GetPackages();
  CHECK(l.size() == many.size() + 1);
  CHECK(CountCi(l, L"NERCFilt") == 1);
  for (const auto &s : many)
    CHECK_MSG(CountCi(l, s.c_str()) == 1, "lost %ls", s.c_str());
}

REGISTRY_TEST(reg_unregister_large_list) {
  auto many = ManyPackages();
  auto with = many;
  with.push_back(L"NERCFilt");
  SetPackages(with);
  CHECK(Unregister() == S_OK);
  CHECK(GetPackages() == many);
}

REGISTRY_TEST(reg_similar_names_not_confused) {
  SetPackages({L"NERCFiltX", L"scecli"});
  CHECK(Register() == S_OK);
  auto l = GetPackages();
  CHECK(CountCi(l, L"NERCFilt") == 1);
  CHECK(CountCi(l, L"NERCFiltX") == 1);
  CHECK(Unregister() == S_OK);
  l = GetPackages();
  CHECK(CountCi(l, L"NERCFilt") == 0);
  CHECK(CountCi(l, L"NERCFiltX") == 1);
  CHECK(CountCi(l, L"scecli") == 1);
}

REGISTRY_TEST(reg_names_case_insensitive) {
  SetPackages({L"scecli", L"nercfilt"});
  CHECK(Register() == S_OK);
  CHECK(CountCi(GetPackages(), L"NERCFilt") == 1);
  CHECK(Unregister() == S_OK);
  auto l = GetPackages();
  CHECK(CountCi(l, L"NERCFilt") == 0);
  CHECK(CountCi(l, L"scecli") == 1);
}

REGISTRY_TEST(reg_unregister_when_absent) {
  SetPackages({L"scecli"});
  CHECK(Unregister() == S_OK);
  CHECK(GetPackages() == std::vector<std::wstring>{L"scecli"});
}

REGISTRY_TEST(reg_wrong_type_left_alone) {
  // A Notification Packages value that is not REG_MULTI_SZ is not ours to
  // rewrite; registration must fail rather than clobber it.
  RawValue rv;
  rv.exists = true;
  rv.type = REG_SZ;
  const wchar_t s[] = L"scecli";
  rv.data.assign(reinterpret_cast<const BYTE *>(s),
                 reinterpret_cast<const BYTE *>(s) + sizeof(s));
  WriteRaw(kLsaKey, kPackagesValue, rv);
  CHECK(FAILED(Register()));
  RawValue after = ReadRaw(kLsaKey, kPackagesValue);
  CHECK(after.type == REG_SZ);
  CHECK(after.data == rv.data);
}

// ---------------------------------------------------------------------------
// Policy configuration (modifies HKLM; --registry only)
// ---------------------------------------------------------------------------

REGISTRY_TEST(cfg_minimum_length_raised) {
  ResetPolicy();
  SetPolicyDword(kMinLengthValue, 14);
  CHECK(!Accepts(L"Abcdefghijk1!"));  // 13
  CHECK(Accepts(L"Abcdefghijkl1!"));  // 14
  ResetPolicy();
}

REGISTRY_TEST(cfg_minimum_length_cannot_go_below_cip) {
  ResetPolicy();
  SetPolicyDword(kMinLengthValue, 4);
  CHECK(!Accepts(L"Abcde1!"));
  CHECK(Accepts(L"Abcdef1!"));
  SetPolicyDword(kMinLengthValue, 0);
  CHECK(!Accepts(L"Abcde1!"));
  ResetPolicy();
}

REGISTRY_TEST(cfg_minimum_length_capped) {
  // Windows passwords are at most 256 characters; a larger setting would lock
  // everyone out, so it is capped.
  ResetPolicy();
  SetPolicyDword(kMinLengthValue, 100000);
  std::wstring pw(256, L'a');
  pw[0] = L'A';
  pw[1] = L'1';
  CHECK(Accepts(pw));
  CHECK(!Accepts(pw.substr(0, 255)));
  ResetPolicy();
}

REGISTRY_TEST(cfg_four_classes) {
  ResetPolicy();
  SetPolicyDword(kMinClassesValue, 4);
  CHECK(!Accepts(L"Abcdefg1"));
  CHECK(Accepts(L"Abcdef1!"));
  ResetPolicy();
}

REGISTRY_TEST(cfg_classes_cannot_go_below_cip) {
  ResetPolicy();
  SetPolicyDword(kMinClassesValue, 1);
  CHECK(!Accepts(L"abcdefgh1"));
  CHECK(Accepts(L"Abcdefg1"));
  ResetPolicy();
}

REGISTRY_TEST(cfg_classes_capped) {
  ResetPolicy();
  SetPolicyDword(kMinClassesValue, 9);
  CHECK(Accepts(L"Abcdef1!"));
  CHECK(!Accepts(L"Abcdefg1"));
  ResetPolicy();
}

REGISTRY_TEST(cfg_wrong_type_ignored) {
  ResetPolicy();
  RawValue rv;
  rv.exists = true;
  rv.type = REG_SZ;
  const wchar_t s[] = L"20";
  rv.data.assign(reinterpret_cast<const BYTE *>(s),
                 reinterpret_cast<const BYTE *>(s) + sizeof(s));
  WriteRaw(kPolicyKey, kMinLengthValue, rv);
  CHECK(Accepts(L"Abcdef1!"));
  ResetPolicy();
}

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

const TestCase *Find(const char *name) {
  for (const auto &c : Registry())
    if (std::strcmp(c.name, name) == 0)
      return &c;
  return nullptr;
}

int RunInProcess(const char *name) {
  const TestCase *c = Find(name);
  if (!c) {
    std::printf("unknown case %s\n", name);
    return 2;
  }
  c->fn();
  std::fflush(stdout);
  return g_failures == 0 ? 0 : 1;
}

DWORD RunIsolated(const char *name) {
  wchar_t self[MAX_PATH * 2];
  GetModuleFileNameW(nullptr, self, MAX_PATH * 2);
  wchar_t wname[256];
  std::swprintf(wname, 256, L"%hs", name);
  std::wstring cmd = L"\"" + std::wstring(self) + L"\" --case " + wname;
  STARTUPINFOW si{};
  si.cb = sizeof(si);
  PROCESS_INFORMATION pi{};
  std::fflush(stdout);
  if (!CreateProcessW(nullptr, &cmd[0], nullptr, nullptr, TRUE, 0, nullptr,
                      nullptr, &si, &pi)) {
    std::printf("    CreateProcess failed (%lu)\n", GetLastError());
    return 0xFFFFFFFF;
  }
  WaitForSingleObject(pi.hProcess, 60000);
  DWORD code = 0xFFFFFFFF;
  GetExitCodeProcess(pi.hProcess, &code);
  if (code == STILL_ACTIVE) {
    TerminateProcess(pi.hProcess, 0xFFFFFFFE);
    code = 0xFFFFFFFE;
  }
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  return code;
}

bool PolicyKeyPresent() {
  HKEY h;
  if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kPolicyKey, 0, KEY_QUERY_VALUE, &h) !=
      ERROR_SUCCESS)
    return false;
  DWORD values = 0;
  RegQueryInfoKeyW(h, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                   &values, nullptr, nullptr, nullptr, nullptr);
  RegCloseKey(h);
  return values > 0;
}

} // namespace

int main(int argc, char **argv) {
  // Keep a crashing child from popping a WER dialog on a desktop machine.
  SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);

  bool registry = false;
  for (int i = 1; i < argc; ++i) {
    if (std::strcmp(argv[i], "--case") == 0 && i + 1 < argc)
      return RunInProcess(argv[i + 1]);
    if (std::strcmp(argv[i], "--list") == 0) {
      for (const auto &c : Registry())
        std::printf("%s%s\n", c.name, c.needs_registry ? " (registry)" : "");
      return 0;
    }
    if (std::strcmp(argv[i], "--registry") == 0)
      registry = true;
  }

  std::printf("NERCFilt tests: %ls\n", DllPath().c_str());

  RawValue saved_packages, saved_len, saved_classes;
  if (registry) {
    saved_packages = ReadRaw(kLsaKey, kPackagesValue);
    saved_len = ReadRaw(kPolicyKey, kMinLengthValue);
    saved_classes = ReadRaw(kPolicyKey, kMinClassesValue);
    ResetPolicy();
  } else if (PolicyKeyPresent()) {
    std::printf("HKLM\\%ls has values on this machine; the default-policy "
                "tests need it absent.\n",
                kPolicyKey);
    return 2;
  }

  int passed = 0, failed = 0, skipped = 0;
  for (const auto &c : Registry()) {
    if (c.needs_registry && !registry) {
      ++skipped;
      continue;
    }
    std::printf("[ RUN  ] %s\n", c.name);
    DWORD code = RunIsolated(c.name);
    if (code == 0) {
      ++passed;
      std::printf("[  OK  ] %s\n", c.name);
    } else {
      ++failed;
      if (code == 1)
        std::printf("[ FAIL ] %s\n", c.name);
      else
        std::printf("[ FAIL ] %s (crashed, exit 0x%08lX)\n", c.name, code);
    }
  }

  if (registry) {
    WriteRaw(kLsaKey, kPackagesValue, saved_packages);
    WriteRaw(kPolicyKey, kMinLengthValue, saved_len);
    WriteRaw(kPolicyKey, kMinClassesValue, saved_classes);
  }

  std::printf("\n%d passed, %d failed, %d skipped (registry tests need "
              "--registry)\n",
              passed, failed, skipped);
  return failed == 0 ? 0 : 1;
}
