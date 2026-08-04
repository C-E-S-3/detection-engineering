---
scraped_at: 2026-08-04T06:00:00Z
source_url: https://github.com/advisories
report_type: threat-intel
severity: high
title: "Crypto-Targeting Supply Chain Wave: coldcard-helpers (PyPI), bip39-generator (npm), instalogin1234 (PyPI)"
---

# Crypto-Targeting Supply Chain Wave — PyPI & npm Malicious Packages (August 2026)

**Source:** GitHub Security Advisory Database (OpenSSF Package Analysis)  
**Published:** 2026-08-03 – 2026-08-04  
**Severity:** High  

## Summary

GitHub's Security Advisory Database published multiple advisories on August 3–4, 2026 documenting malicious packages distributed via PyPI and npm. Three packages are notable for explicitly targeting cryptocurrency wallets and credential stores: **coldcard-helpers** (PyPI), **@zzzgenesis00/bip39-generator** (npm), and **instalogin1234** (PyPI). These represent a coordinated wave of supply chain infostealer packages, each with a confirmed SHA256 hash, targeting developer and crypto-user environments.

A fourth naming pattern — **internallib_v\*** (npm) — represents a separate typosquatting campaign (`internallib_v524`, `internallib_v568`, `internallib_v688`) with no distinct public IOCs beyond package names; those packages are noted for context but not the primary focus here.

## Technical Details

### coldcard-helpers (PyPI ≤ 1.4.2) — GHSA-8vw6-pp4v-8j32

- **Type:** Python infostealer
- **Capability:** Exfiltrates environment variables, cryptocurrency wallet private keys, SSH private keys
- **C2 method:** Telegram bot (specific bot ID not publicly disclosed)
- **Masquerade:** Named to impersonate tooling for the Coldcard hardware wallet (a Bitcoin hardware wallet)
- **Confirmed SHA256:** `127a096109f7b5b2bbedf7f6a9fc2e7baa706e93704ebd52615e744a9838fbc3`
- **Affected versions:** ≤ 1.4.2

### @zzzgenesis00/bip39-generator (npm 3.1.2) — GHSA-f5gh-74gw-hjvx

- **Type:** JavaScript infostealer / beaconing package
- **Capability:** Communicates with malicious external domain at install/import time
- **Masquerade:** Named to impersonate BIP-39 mnemonic seed phrase generation tooling (cryptocurrency wallet setup utility)
- **Confirmed SHA256:** `5cd50fa982c125844b76d3527f878bd6a171b497e86fd7cbcccfc56d22000da4`
- **Affected version:** 3.1.2

### instalogin1234 (PyPI 0.0.1) — GHSA-7929-ff6q-qmmh

- **Type:** Python credential stealer
- **Capability:** Harvests Instagram session credentials and exfiltrates them to an attacker-controlled Discord channel webhook
- **C2 method:** Discord webhook exfiltration
- **Confirmed SHA256:** `f6ed64b38b3e872668e1d36a02c53136da1ab70ec9dacd2ac3b7d38c31794ebe`
- **Affected version:** 0.0.1

## Targeting

- **Platform:** Developer workstations, CI/CD environments, cryptocurrency developers
- **Geography:** Global
- **Sectors:** Cryptocurrency / fintech developers, general software developers
- **Attribution:** Unattributed; packages appear to originate from independent or loosely affiliated threat actors using commodity infostealer techniques

## IOCs

### Hashes

| Indicator | Type | Context |
|-----------|------|---------|
| `127a096109f7b5b2bbedf7f6a9fc2e7baa706e93704ebd52615e744a9838fbc3` | SHA256 | coldcard-helpers PyPI ≤1.4.2 — crypto wallet key infostealer |
| `5cd50fa982c125844b76d3527f878bd6a171b497e86fd7cbcccfc56d22000da4` | SHA256 | @zzzgenesis00/bip39-generator npm 3.1.2 — malicious BIP-39 package |
| `f6ed64b38b3e872668e1d36a02c53136da1ab70ec9dacd2ac3b7d38c31794ebe` | SHA256 | instalogin1234 PyPI 0.0.1 — Instagram credential stealer |

### Package Names (Hunt Indicators)

| Package | Registry | Malicious Version(s) |
|---------|----------|----------------------|
| `coldcard-helpers` | PyPI | ≤ 1.4.2 |
| `@zzzgenesis00/bip39-generator` | npm | 3.1.2 |
| `instalogin1234` | PyPI | 0.0.1 |
| `internallib_v524` | npm | all versions |
| `internallib_v568` | npm | all versions |
| `internallib_v688` | npm | all versions |

## MITRE ATT&CK TTPs

| Technique | ID | Notes |
|-----------|----|-------|
| Supply Chain Compromise: Compromise Software Dependencies and Development Tools | T1195.001 | Malicious packages published to PyPI and npm public registries |
| User Execution: Malicious File | T1204.002 | Package installs/imports execute malicious code |
| Credentials from Password Stores | T1555 | coldcard-helpers targets crypto wallet private keys and SSH keys |
| Steal Web Session Cookie | T1539 | instalogin1234 harvests Instagram session credentials |
| Exfiltration Over Web Service: Exfiltration to Code Repository | T1567.001 | Discord webhook (instalogin1234) and Telegram bot (coldcard-helpers) used for exfiltration |
| Obfuscated Files or Information | T1027 | Packages masquerade as legitimate crypto tooling to deceive developers |

## Kill Chain

- **Delivery** — Malicious packages published to public PyPI/npm registries under crypto-themed names
- **Exploitation** — Developer installs or imports package; malicious code executes at install/import time
- **Actions on Objectives** — Exfiltration of crypto wallet private keys, SSH keys, environment variables, and session credentials to Telegram/Discord attacker infrastructure

## Remediation

| Action | Priority |
|--------|----------|
| Scan CI/CD pipelines and developer workstations for coldcard-helpers ≤1.4.2, @zzzgenesis00/bip39-generator 3.1.2, instalogin1234 0.0.1 | High |
| Scan for confirmed SHA256 hashes in EDR / file integrity tooling | High |
| Audit Python and Node.js package manifests (requirements.txt, package.json, poetry.lock, package-lock.json) for these package names | High |
| Review outbound Telegram and Discord webhook traffic from developer workstations | Medium |
| Enforce private registry mirroring or package allowlisting to prevent direct public registry install in CI/CD | Medium |

## References

- [GitHub Advisory GHSA-8vw6-pp4v-8j32 — coldcard-helpers infostealer](https://github.com/advisories/GHSA-8vw6-pp4v-8j32)
- [GitHub Advisory GHSA-f5gh-74gw-hjvx — @zzzgenesis00/bip39-generator malicious package](https://github.com/advisories/GHSA-f5gh-74gw-hjvx)
- [GitHub Advisory GHSA-7929-ff6q-qmmh — instalogin1234 credential stealer](https://github.com/advisories/GHSA-7929-ff6q-qmmh)
- [MITRE ATT&CK — T1195.001: Supply Chain Compromise: Software Dependencies](https://attack.mitre.org/techniques/T1195/001/)
- [MITRE ATT&CK — T1555: Credentials from Password Stores](https://attack.mitre.org/techniques/T1555/)
