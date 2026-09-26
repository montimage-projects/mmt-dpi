---
layout: default
title: "Distribution package submission checklist"
---

# Distribution package submission checklist

> **Historical report (2026-09-16):** the former build checklist described
> `mmt-dpi 1.7.10` and originally omitted `libmmt_tdicom.so` from its library
> list. Those results do not establish current package contents or official
> archive availability; package payloads are checked by
> `tools/ci/check-package-deps.sh --verify-package`.

## Current upstream packages (not official distribution packages)

The release matrix builds local `.deb` files for Ubuntu 22.04, Ubuntu 24.04,
and Debian 12 and `.rpm` files for Rocky Linux 9 and CentOS Stream 9, on
amd64 and arm64 (`.github/workflows/release-packages.yml:78-91`). Its build
script installs **the generated local artifact** with `apt-get` or `dnf`/`yum`
and runs an installed consumer (`tools/ci/build-package.sh:116-154`). Tagged
releases upload those files to **GitHub Releases**, not to distribution archives
(`.github/workflows/release-packages.yml:259-308`). These are upstream build
and local-install targets, **not a verified official-repository support matrix**.

The prior version of this checklist described publishing a self-hosted APT
repository under `/var/www/html`, adding its URL to `sources.list`, and using
`apt-key`. That would create a **third-party repository**, not an official
Ubuntu or Debian package, and `apt-key` should not be used for new setup.
Those instructions have been removed to avoid presenting a self-hosted channel
as fulfillment of issue #475.

To use the existing upstream-built files, follow the verified-download and
local-file installation instructions in the [repository README](https://github.com/montimage-projects/mmt-dpi/blob/main/README.md#pre-built-packages-upstream-github-releases-not-distribution-archives).
Do not advertise `apt install mmt-dpi` or `dnf install mmt-dpi` without a local
file as available from a distribution until the corresponding archive actually
indexes and serves the package.

## Official-channel targets and blockers

| Candidate distribution | Official channel to pursue | Current evidence |
|------------------------|----------------------------|------------------|
| Ubuntu 22.04 / 24.04 | Ubuntu archive (APT) | Upstream `.deb` built and installed locally in CI; no archive acceptance verified |
| Debian 12 | Debian archive (APT) | Upstream `.deb` built and installed locally in CI; no archive acceptance verified |
| Rocky Linux 9 | Distribution-maintained repository (DNF) | Upstream `.rpm` built and installed locally in CI; no repository acceptance verified |
| CentOS Stream 9 | Distribution-maintained repository (DNF) | Upstream `.rpm` built and installed locally in CI; no repository acceptance verified |

This table identifies **candidates**, not officially supported versions or
approved distribution channels. A GitHub release, PPA, and project-hosted APT
repository are not the official distribution archives requested in #475.

Before proposing any official channel, a human maintainer must:

1. Select a target distribution, release series, package name, and maintenance
   owner; check that archive's current policies and sponsorship process.
2. Audit redistribution rights for **all shipped source and dependencies**.
   The repository's `LICENSE:1-4` is Apache-2.0, but the current RPM recipe
   declares `License: proprietary` (`sdk/Makefile:217`); do not change this
   label to a different blanket claim without a provenance audit.
3. Prepare **source packaging** and archive-compliant build/install metadata
   for the chosen target. The existing `sdk/Makefile:156-194` creates a binary
   `.deb` under `/opt/mmt`; a binary generated locally is not a distro source
   package. Review dependency declarations and policy requirements rather
   than submitting that file as-is.
4. Build and test in clean environments for each proposed release/architecture,
   then have an authorized maintainer seek external sponsorship/review. Do not
   upload to any distribution archive without explicit authorization.
5. After independent archive acceptance, verify the exact published version
   resolves from **default official sources** on a fresh installation, and
   confirm install/remove plus a working SDK consumer. Only then document a
   plain `apt install mmt-dpi` or `dnf install mmt-dpi` and mark the corresponding
   version/channel supported.

**Status for #475:** No official-channel availability or default-repository
package-manager installation is established by this checklist. Publication,
acceptance, and version-specific instructions remain external work; this
repository change must not close the issue.
