# Security policy

NERCFilt runs inside LSASS on domain controllers and servers. A bug in it
can crash the security subsystem or let a weak password through, so security
reports are taken seriously.

## Reporting a vulnerability

Please report vulnerabilities **privately** through GitHub:
**Security → Report a vulnerability** on this repository
([direct link](https://github.com/mcarey42/NERCFilt/security/advisories/new)).

Please do not open a public issue for a security problem.

A useful report includes:

* the NERCFilt version (`Install-NERCFilt.ps1 -Status` shows it) and Windows
  version and architecture
* what happens and what you expected, with steps or a test case that shows
  it (the test harness in `tests/` makes this easy)
* the impact as you understand it, for example an LSASS crash, a password
  accepted that should be rejected, or an elevation of privilege.

You can expect an acknowledgement within a week. Fixes are released as a new
version with a GitHub security advisory, crediting the reporter unless they
prefer otherwise.

## Supported versions

| Version | Supported |
|---|---|
| 2.x | Yes |
| 1.x | **No.** 1.0 can crash LSASS and can accept non-compliant passwords. Upgrade to 2.x. |

## Verifying a release

Release binaries are not yet code-signed. Each release instead includes:

* `SHA256SUMS.txt`, covering each zip and the `NERCFilt.dll` inside it, and
* GitHub build-provenance attestations, which show that a file was built
  from this repository by its release workflow at a specific commit.

To verify a downloaded DLL or zip with the [GitHub CLI](https://cli.github.com/):

```
gh attestation verify NERCFilt.dll --repo mcarey42/NERCFilt
```
