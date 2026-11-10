# Maintaining and releasing NERCFilt

## Making a release

1. On a branch, update `NERCFilt/version.h` (and the "Changes" section of
   `README.md`), open a pull request, and merge it once CI is green.
2. Tag the merge commit on `main` and push the tag:

   ```
   git checkout main
   git pull
   git tag -a v2.0.1 -m "NERCFilt 2.0.1"
   git push origin v2.0.1
   ```

   The tag must be `v` followed by the version in `version.h`, or the
   workflow stops before building.
3. The **Build and test** workflow builds x64 and ARM64 natively and runs all
   tests, including the install script. It then generates build-provenance
   attestations and creates a **draft** release containing:
   * `NERCFilt-<version>-x64.zip` and `NERCFilt-<version>-ARM64.zip`
     (DLL, PDB, `Install-NERCFilt.ps1`, README, LICENSE)
   * `SHA256SUMS.txt` (each zip and each DLL inside it).
4. Review the draft on the Releases page: edit the generated notes and check
   the assets. Then **Publish**. Nothing is public until you do, and with
   immutable releases enabled the assets cannot be changed afterwards.

If a build fails, fix it on `main`, delete the tag (`git push --delete origin
v2.0.1` and `git tag -d v2.0.1`), and tag again. Re-running against an
existing *draft* replaces its assets. The workflow refuses to touch a
release that has already been published.

## Repository settings

These settings are not stored in the repository and must be set on GitHub.
They were recommended when 2.0 was released.

**Settings → General**
* Description: *Windows LSA password filter enforcing NERC CIP-007-6 R5.5
  password rules*.
  Topics: `windows`, `password-filter`, `lsa`, `nerc-cip`,
  `active-directory`, `security`.
* Features: turn off **Wikis** and **Projects** (unused). Keep **Issues**.
* Pull Requests: turn on **Automatically delete head branches**.
* Releases: turn on **Enable release immutability**.

**Settings → Rules → Rulesets** → new branch ruleset for the default
branch, set to *Active*:
* Restrict deletions, and Block force pushes.
* Require a pull request before merging. Use 0 required approvals while
  there is a single maintainer; the admin can bypass.
* Require status checks to pass, selecting the three **Build and test**
  jobs: `x64 on windows-2022`, `x64 on windows-2025`,
  `ARM64 on windows-11-arm`.

**Settings → Rules → Rulesets** → new tag ruleset targeting `v*`, set to
*Active*: Restrict updates, Restrict deletions, Block force pushes, with
*Repository admin* in the bypass list. This stops a release tag from being
moved to a different commit. Only an admin can delete and re-create a tag,
for example to retry a failed release that was never published.

**Settings → Actions → General**
* Workflow permissions: **Read repository contents and packages
  permissions**. The workflow requests write access only in the release
  job.
* Leave **Allow GitHub Actions to create and approve pull requests** off.
* For fork pull requests, require approval for first-time contributors (the
  default).

**Settings → Advanced Security** (*Code security* on some plans)
* **Private vulnerability reporting**: Enable (`SECURITY.md` points here).
* **Dependabot alerts** and **Dependabot security updates**: Enable.
  `.github/dependabot.yml` handles version updates for the pinned actions.
* **Secret scanning** and **Push protection**: Enable.

## Pinned actions

Every action in `.github/workflows/build.yml` is pinned to a full commit
SHA, with the version in a comment. The release binaries end up inside
LSASS, so a tag that moved to malicious code must not be able to change
what gets built. Dependabot opens grouped weekly PRs to update the pins;
review the upstream changes before merging them.
