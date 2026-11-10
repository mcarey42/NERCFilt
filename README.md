# NERCFilt 2.0

NERCFilt is a Windows password filter DLL that enforces the NERC CIP-007-6
R5.5 password parameters for every password change and every password set
by an administrator, on a single machine or (installed on all domain
controllers) across an Active Directory domain.

It is a standard LSA *password filter*: LSA loads it at boot and calls it
before accepting any new password. No service or agent is involved.

## Policy

By default a password is accepted only if it has:

| Rule | Default | CIP-007-6 |
|---|---|---|
| Minimum length | 8 characters | R5.5.1 |
| Character classes | at least 3 of: upper case, lower case, digit, symbol | R5.5.2 |

Upper and lower case include non-ASCII letters (for example `Ü` and `é`),
classified by Windows (`GetStringTypeW`, `CT_CTYPE1`). Spaces do not count
as symbols.

The rules apply to administrative password sets and resets as well as to
users changing their own passwords.

**Exempt accounts.** Accounts whose names end in `$` are not filtered. These
are computer, inter-domain trust and (group) managed service accounts, whose
passwords Windows generates itself. Filtering them would break domain joins
and secure-channel resets. A *user* account deliberately named with a
trailing `$` would also be exempt. If you allow such names, cover them by
procedure.

### Making the policy stricter

Optional `REG_DWORD` values under `HKLM\SOFTWARE\NERCFilt`:

| Value | Range | Default |
|---|---|---|
| `MinimumLength` | 8 – 256 | 8 |
| `MinimumCharacterClasses` | 3 – 4 | 3 |

Values below the CIP minimums are raised to them, larger values are capped,
and values of any other type are ignored. The filter can therefore never be
configured weaker than CIP-007-6. Changes take effect on the next password
change; no restart is needed. Example (14 characters, all four classes):

```bat
reg add HKLM\SOFTWARE\NERCFilt /v MinimumLength /t REG_DWORD /d 14 /f
reg add HKLM\SOFTWARE\NERCFilt /v MinimumCharacterClasses /t REG_DWORD /d 4 /f
```

NERCFilt works alongside the built-in Windows password policy, fine-grained
password policies and other password filters such as Microsoft Entra
Password Protection. A password must satisfy all of them.

## Requirements

* Windows Server 2016 or later (or Windows 10 1607 or later).
* x64 or ARM64. 32-bit Windows is not supported.
* No runtime dependencies: the C runtime is linked statically.

## Install

Download `NERCFilt-<version>-x64.zip` (or `-ARM64`) from the
[Releases](../../releases) page and verify it (see
[Verifying a download](#verifying-a-download)). Extract it, then run this in
an **elevated** PowerShell on each machine (every domain controller, for
domain-wide enforcement):

```powershell
.\Install-NERCFilt.ps1
```

The script:
1. checks that the DLL matches the machine's architecture and that Windows is
   new enough
2. refuses to install if LSA Protection is on (see below) unless you pass
   `-Force`
3. copies `NERCFilt.dll` to `System32` (an older copy is renamed, not
   overwritten, because LSASS may have it loaded) and registers it
4. prints the installed version and SHA-256 for your baseline records, and
   offers to restart.

`-WhatIf` shows what it would do, and `-NoRestartPrompt` is for scripted
deployments. You may need `Unblock-File .\Install-NERCFilt.ps1` first, or
`powershell -ExecutionPolicy Bypass -File .\Install-NERCFilt.ps1`, depending
on your execution policy.

**Restart the machine afterwards**: LSA reads its list of password filters
only at boot. After the restart:

```powershell
.\Install-NERCFilt.ps1 -Status
```

`-Status` shows the installed version and hash, whether NERCFilt is
registered and loaded, the LSA Protection state, the effective policy, and
any recent Code Integrity events about the DLL. Then test the filter by
trying to set a password that breaks the policy, for example `abcdefgh`, on
a test account.

<details>
<summary>Manual install without the script</summary>

```bat
copy NERCFilt.dll %SystemRoot%\System32\
regsvr32 %SystemRoot%\System32\NERCFilt.dll
```

`regsvr32` adds `NERCFilt` to the REG_MULTI_SZ value
`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages` and leaves
every other entry in place. Then restart.
</details>

### LSA Protection (RunAsPPL)

When LSA Protection is enabled, LSASS loads only plug-ins that meet
Microsoft's signing requirements for protected LSA. Recent Windows versions
enable it by default in more situations. The release binaries are currently
**unsigned**, so on a protected LSA the filter will not load and the policy
will not be enforced. The install script checks for this. If you install
anyway, `-Status` and the `Microsoft-Windows-CodeIntegrity/Operational`
event log show whether the DLL was blocked.

### Verifying a download

Each release includes `SHA256SUMS.txt`, covering each zip and the
`NERCFilt.dll` inside it:

```powershell
Get-FileHash .\NERCFilt-2.0.0-x64.zip
```

Releases also carry GitHub
[build-provenance attestations](https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations),
which prove that a file was built from this repository by its release
workflow. Check one with the [GitHub CLI](https://cli.github.com/):

```
gh attestation verify NERCFilt.dll --repo mcarey42/NERCFilt
```

## Uninstall

In an elevated PowerShell:

```powershell
.\Install-NERCFilt.ps1 -Uninstall
```

The script unregisters the filter and removes the DLL; if LSASS still has it
loaded, the script tells you to delete it after the restart. Without the
script: run `regsvr32 /u %SystemRoot%\System32\NERCFilt.dll`, restart, then
delete the DLL.

## Building

Visual Studio 2022 or later with the *Desktop development with C++*
workload (add the ARM64 build tools for ARM64). Open `NERCFilt.sln`, or:

```bat
msbuild NERCFilt.sln /m /p:Configuration=Release /p:Platform=x64
```

Output goes to `build\<platform>\<configuration>\`. Release builds are
deterministic (`/Brepro`), so rebuilding the same source with the same
toolset gives the same DLL.

## Tests

`NERCFiltTests.exe` (built alongside the DLL) loads `NERCFilt.dll` the way
LSA does and runs each case in its own process, so a crash shows up as a
test failure. Every password is placed directly in front of a no-access
guard page with no terminator, so any read past its length faults.

```bat
build\x64\Release\NERCFiltTests.exe
build\x64\Release\NERCFiltTests.exe --registry
```

`--registry` also tests registration and policy configuration. It edits
`Notification Packages` and `HKLM\SOFTWARE\NERCFilt` and restores them
afterwards. Run it elevated, and only on disposable machines such as CI
runners.

## Continuous integration and releases

`.github/workflows/build.yml` builds and tests every push to `main` and every
pull request on Windows Server 2022 and 2025 (x64) and Windows 11 ARM64. That
includes the DLL tests, a PSScriptAnalyzer lint of the install script, and a
real install, status check and uninstall under Windows PowerShell 5.1.

Pushing a tag that matches `NERCFilt/version.h` (for example `v2.0.0`)
builds and tests both architectures, generates build-provenance
attestations, and creates a **draft** release. A maintainer publishes it
after review. [docs/RELEASING.md](docs/RELEASING.md) describes the procedure
and the recommended repository settings. Security problems: see
[SECURITY.md](SECURITY.md).

## Changes in 2.0

* **Fixed:** minimum length was counted in bytes, so 1.0 enforced 5
  characters instead of 10.
* **Fixed:** 1.0 read past the end of the password inside LSASS. It could
  crash LSASS (forcing a reboot) or accept a weak password based on whatever
  memory followed it.
* **Fixed:** 32-bit exports were decorated or used the wrong calling
  convention. 32-bit support has been dropped.
* **Fixed:** registration crashed when `Notification Packages` was larger
  than 1 KB or missing, matched names by prefix and case-sensitively,
  rewrote values of the wrong type, and reported failures as success.
* **Changed:** policy updated from CIP-005-3/CIP-007-3 to CIP-007-6 R5.5
  (8 characters, 3 of 4 classes), configurable to stricter values.
* **Changed:** administrative password sets are now filtered; `$` accounts
  are exempt.
* **Changed:** no heap allocation or exceptions inside LSASS; the
  classification buffer is scrubbed after use.
* **New:** ARM64 builds, VS 2022+ toolchain, Server 2016 minimum, hardened
  build (CFG, CET, /sdl, /W4 /WX), version resource, automated tests and
  release pipeline.
* **New:** `Install-NERCFilt.ps1` (install, uninstall, status), build
  provenance attestations, draft-then-publish releases, SHA-pinned CI
  actions with Dependabot, and a security policy.
* **License:** now MIT (was LGPL 2.1).

## License

MIT. See [LICENSE](LICENSE).

## Author

Written by Mark Carey, Peak Security, Inc. (https://www.peaksec.com), originally as a favor
to a friend.

*I'm a trouble-shooter, nobody knows the troubles I've shot...*
