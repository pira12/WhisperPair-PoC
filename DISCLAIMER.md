# Disclaimer

WhisperPair is a **proof-of-concept exploitation tool** released for security
research, education, and defensive testing. Read this document in full before
running any code in this repository.

## Authorized use only

You may use, build, or run this software **only** against:

1. Devices you own outright, or
2. Devices for which you have **explicit, written authorization** from the
   owner to perform security testing.

Anything else - including testing on devices in shared spaces, on a friend's
earbuds without permission, on devices owned by your employer without a
written authorization, or on devices belonging to neighbours, colleagues, or
strangers - is almost certainly illegal in your jurisdiction. Bluetooth
exploitation can constitute unauthorized access to a computer system,
unauthorized interception of electronic communications, and (when audio is
captured) illegal eavesdropping. Penalties typically include criminal
prosecution and civil liability.

By cloning, building, or running this code you confirm that you understand
this and accept full responsibility for your actions.

## Capabilities and risks

This tool is designed to demonstrate the impact of a Bluetooth pairing
weakness. In its full form it can:

- Force-pair with vulnerable Bluetooth devices without user consent
- Hijack audio profiles (HFP/A2DP) to access a device's microphone
- Stream the captured microphone audio in real time
- Inject a persistent Account Key that enables long-term tracking via
  Find My Device-style networks

**Running the eavesdropping flow against another person without consent is
illegal in most jurisdictions even if you "own the laptop you ran it from".**
The act of capturing someone's audio is what is regulated, not the hardware
you used.

## No warranty

This software is provided "AS IS", without warranty of any kind. The
contributors are not responsible for any damage to devices, loss of data,
service degradation, or legal consequences arising from its use. See
`LICENSE` for the full warranty disclaimer.

## Research identifiers

The "CVE-2025-36911" identifier used throughout this repository is the
identifier this proof-of-concept tracks against. Treat the identifier as a
research label until you have independently verified its status (assigned,
disputed, or rejected) on an authoritative source such as the
[CVE Program](https://www.cve.org/) or the
[NVD](https://nvd.nist.gov/). Do not use this repository as evidence that
any specific vendor product is currently vulnerable in the wild.

## Responsible disclosure

If you discover a vulnerability while working with this tool, follow
coordinated disclosure: report it to the vendor first, give them a
reasonable remediation window, and only publish details once a fix is
available or the disclosure deadline has elapsed. See `SECURITY.md` for the
process used by this project.

## Take it down

If you are a vendor, device owner, or rights-holder who believes this
repository should be modified or taken down, open an issue or contact the
maintainer directly and the request will be considered in good faith.
