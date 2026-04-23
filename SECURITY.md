# Security policy

## Reporting a vulnerability in this repository

If you find a security issue in the WhisperPair PoC code itself - for
example, an unsafe deserialization in `app.py`, a path-traversal in a
Flask route, or an issue that lets the dashboard be turned against the
host running it - please **do not open a public GitHub issue**.

Instead, open a [private security advisory](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository, or email the maintainer at the address listed on
their GitHub profile. Include:

- A short description of the issue and its impact
- Reproduction steps or a minimal proof-of-concept
- The commit hash you reproduced against

The maintainer will acknowledge receipt within a reasonable timeframe and
work with you on a fix. Coordinated disclosure is preferred.

## Reporting a vulnerability in a third-party device

This repository targets a Bluetooth pairing weakness in third-party
devices. If you discover a *new* vulnerability in a vendor's product
while using this tool, **report it to the vendor first**:

1. Find the vendor's official security contact (often `security@vendor.tld`,
   a HackerOne / Bugcrowd program, or a published `security.txt`).
2. Send a clear write-up: affected product, firmware version, reproduction
   steps, suggested mitigation.
3. Agree on a disclosure timeline (90 days is the common default).
4. Only publish details after a fix is available or the agreed deadline
   has passed without a response.

Do not test against devices you do not own or do not have written
authorization to test. See `DISCLAIMER.md`.

## Scope

In scope for this repository:

- Bugs in the Python backend, Flask routes, Socket.IO handlers
- Bugs in the React dashboard
- Bugs in the Android companion app
- Issues that allow the tool to be misused beyond its stated scope

Out of scope:

- Reports of the tool "working as designed" against a vulnerable device
- Theoretical attacks without a reproducer
- Issues in third-party dependencies (report those upstream)
