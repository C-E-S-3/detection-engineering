---
scraped_at: 2026-10-24T00:00:00Z
source_url: https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/
report_type: threat-intel
severity: critical
title: "Inside the LiteLLM 1.107.0 Supply Chain Compromise: Credential Theft Through Python Startup Hooks"
---

# Microsoft MSTIC: LiteLLM 1.107.0 Supply Chain — PRIVCOLLECT Credential Stealer via Python Startup Hooks

**Date:** 2026-10-23
**Source:** Microsoft Security Blog / Microsoft Threat Intelligence Center (MSTIC)
**Advisory ID:** TVM-2026-0003
**Severity:** Critical
**Status:** Extended analysis of the October 2026 LiteLLM supply chain attack; extends the October 22 community reports

---

## Executive Summary

Microsoft MSTIC published an extended technical breakdown of the LiteLLM 1.107.0 supply chain attack, designating the malicious credential-stealer component as **PRIVCOLLECT**. This report documents 8 additional file hashes not contained in earlier community reports (including Windows wheel, macOS x86_64 wheel, and ARM/musl Linux wheel variants), a C2 dead-drop resolver pattern using GitHub raw content, AES-256-CBC payload encryption with RSA-wrapped session keys, and a lookalike GitHub organization used to host the dead-drop pointing domain.

Earlier community analysis (StepSecurity, Wiz, Datadog — October 21–22) covered the core attack chain. This Microsoft analysis adds full hash coverage across all 7 distributed wheel variants, Windows-specific artifact paths, the PRIVCOLLECT designation, and detailed analysis of the encryption and exfiltration mechanism.

---

## New Findings vs. October 22 Reports

| Item | Status |
|------|--------|
| PRIVCOLLECT malware designation | **New** — not in earlier reports |
| TVM-2026-0003 advisory | **New** |
| 8 additional SHA-256 hashes | **New** — Windows/x86_64 macOS/ARM/musl Linux wheel variants and Windows-specific payload files |
| AES-256-CBC + RSA key wrapping | **New** — encryption detail not previously published |
| GitHub dead-drop resolver path | **New** — C2 pointing mechanism via `raw.githubusercontent.com` |
| Lookalike GitHub org `Berri-AI/litellm` | **New** — separate from legitimate `BerriAI/litellm` |
| `/tmp/.pc_once_72129118c59f5636c0bb` specific artifact | **New** — full lock file name now confirmed |
| `/tmp/.pc_e_*` OpenSSL staging directories | **New** — Windows temp staging path equivalent |
| Microsoft detection names (Trojan:PyPI/LiteLlmSupplyChain.A/B/C) | **New** |
| Expanded MITRE coverage (T1546.018, T1027.013, T1140, T1552.004/005, T1082, T1016, T1005, T1102.001, T1105) | **New** |

---

## Malware: PRIVCOLLECT

Microsoft designated the credential-stealer component as **PRIVCOLLECT**. It operates in three stages:

1. **`cook.pth`** — Python `.pth` persistence hook placed in `site-packages/`. Executes on every Python interpreter invocation, including subprocesses spawned by CI runners, IDE tooling, and developer shells, before any user code runs. Sub-technique T1546.018 (.pth file startup hook).

2. **`sitecustomize.py`** — The core PRIVCOLLECT credential harvester. Collects:
   - AWS credentials (`~/.aws/credentials`, environment variables `AWS_*`, `~/.aws/config`)
   - GCP application default credentials (`~/.config/gcloud/application_default_credentials.json`)
   - Azure credentials (`~/.azure/credentials`, `AZURE_*` environment variables)
   - SSH private keys (`~/.ssh/id_*`, all private keys regardless of name)
   - TLS/X.509 private keys and certificate bundles
   - Browser credential stores (Chrome/Chromium, Firefox, Edge — login data, cookies, secure notes)
   - LiteLLM proxy database configuration and master keys
   - All environment variables containing `KEY`, `SECRET`, `TOKEN`, `PASSWORD`, `CREDENTIAL`, `AUTH`

3. **`cook.py`** — Hourly remote Python code execution loader. Uses C2 dead-drop to retrieve the current payload URL, then downloads and executes arbitrary Python. Runs in a background thread; does not block the host application.

### Encryption and Exfiltration Mechanism

PRIVCOLLECT encrypts collected credentials before exfiltration:

1. Generates a random 256-bit AES session key per run.
2. Encrypts collected data with AES-256-CBC (random IV per record).
3. Wraps the AES session key with an embedded RSA-2048 public key (hardcoded in `sitecustomize.py`).
4. Posts the encrypted blob via HTTP to `http://www.litellm[.]dev/healthcheck` with `Content-Type: application/octet-stream`.
5. Uses a lock file (`/tmp/.pc_once_<fingerprint>`) to prevent duplicate exfiltration per-host. The specific lock file name is `/tmp/.pc_once_72129118c59f5636c0bb`.
6. Uses `/tmp/.pc_e_*` directories as temporary staging for OpenSSL operations.

### C2 Dead-Drop Resolver

`cook.py` retrieves its hourly payload pointer via a dead-drop URL:

```
https://raw.githubusercontent.com/letters9813/pythonclient-test/main/domain.txt
```

This URL served an attacker-controlled domain pointing to the live C2 server for the remote code execution loader. This GitHub repository (`letters9813/pythonclient-test`) is **not** associated with the LiteLLM project. GitHub has taken down the repository, but the pattern should be monitored in egress logs — Python processes making unanticipated outbound requests to `raw.githubusercontent.com` for non-package-manager purposes may indicate active PRIVCOLLECT infections.

### Lookalike GitHub Organization

The attackers registered a GitHub organization named `Berri-AI` (hyphen) as distinct from the legitimate organization `BerriAI` (no hyphen). The lookalike organization `github.com/Berri-AI/litellm` was used as a staging repository before being taken down.

---

## IOCs

### File Hashes (SHA-256) — New in This Report

| Hash | File | Platform | Context |
|------|------|----------|---------|
| `03ac2a8b752605d1d7710979c17ff18b03dd978203ba23ba97fd8ce3d6f897ea` | `cook.py` | Windows (win_amd64 wheel) | PRIVCOLLECT RCE loader — Windows variant |
| `b6122440d0d9cb1eb1ade9933f49214da8c31288de7710c076c2680dfa528465` | `sitecustomize.py` | Windows (win_amd64 wheel) | PRIVCOLLECT credential stealer — Windows variant |
| `84dc8c82c0a4a4a62552ef826b49fcc86d1a5c4a5d0f2c06665723f93d129d7d` | `cook.pth` | Windows (win_amd64 wheel) | PRIVCOLLECT .pth persistence hook — Windows variant |
| `7598727f209d717041db37f7dca271d3a7d328a279890e0e1d55375729aeb86d` | `litellm-1.107.0-py3-none-macosx_10_12_x86_64.whl` | macOS x86_64 | Tampered wheel — macOS x86_64 variant |
| `668169d35b87bf51324080390b1b1c5ab12bd335cfe5f1a99e3689abd5e02ae6` | `litellm-1.107.0-py3-none-manylinux_2_28_aarch64.whl` | Linux (manylinux aarch64) | Tampered wheel — Linux AArch64 variant |
| `c2e32d0ce2548aa662c18bf5001911a79fe5b30cf8357132275add02fdcde054` | `litellm-1.107.0-py3-none-musllinux_1_2_aarch64.whl` | Linux (musl aarch64) | Tampered wheel — musl Linux AArch64 variant |
| `1bbce8caa94f01c0aaa0b7ddae51553a8a32e1ce53d96d44fe583272aff7ad00` | `litellm-1.107.0-py3-none-musllinux_1_2_x86_64.whl` | Linux (musl x86_64) | Tampered wheel — musl Linux x86_64 variant |
| `12d4ccc5c6f8d35cf4f2cf233b7f3e418e863e657d81ff5f5fc9e210005b9484` | `litellm-1.107.0-py3-none-win_amd64.whl` | Windows | Tampered wheel — Windows x64 variant |

### File Hashes — Previously Reported (for completeness)

| Hash | File | Source |
|------|------|--------|
| `7f191632e7320705d154b85204f1ae546b543acbd7e8861229b76f5042b92bdb` | `cook.pth` (Linux/macOS arm64) | BerriAI Issue #47826 |
| `34bef04fe88ac9d0aae0475630b1738681d15b94f233ac8aa46eacf5968305fa` | `sitecustomize.py` (Linux/macOS arm64) | BerriAI Issue #47826 |
| `9dd0a3926f96a37eb86cf1ee2310d9be93139cc4ebef3ef9e2efe9531390be25` | `cook.py` (Linux/macOS arm64) | BerriAI Issue #47826 |
| `0aaf7ba346d41ef2f40390436738b001180d5a1c03aa093f121078a9969d9a1a` | `litellm-1.107.0-py3-none-macosx_14_0_arm64.whl` | BerriAI Issue #47826 |
| `462d0c9f67ca522d9e0e4acd245e90b36ce0d5353604a66bb7c43a1ec4a6fcf7` | `litellm-1.107.0-py3-none-manylinux_x86_64.whl` | BerriAI Issue #47826 |

*Note: The `cook.pth` hash in the October 22 report (`7f191632...92bd`) appears to be missing its final hex character. The authoritative 64-character hash from this Microsoft report is `7f191632e7320705d154b85204f1ae546b543acbd7e8861229b76f5042b92bdb`.*

### Network IOCs

| Indicator | Type | Context |
|-----------|------|---------|
| `litellm[.]dev` | Domain | Attacker-registered apex domain (see also `www.litellm[.]dev` already tracked); legitimate LiteLLM project uses `litellm.ai` |
| `www.litellm[.]dev` | Domain | Exfiltration endpoint — HTTP POST to `/healthcheck`; already tracked (2026-10-21) |
| `raw.githubusercontent.com/letters9813/pythonclient-test/main/domain.txt` | URL Path | C2 dead-drop resolver; GitHub has taken down the repo; monitor Python processes fetching non-pypi content from raw.githubusercontent.com |

---

## Host Artifacts

| Artifact | Platform | Context |
|----------|----------|---------|
| `cook.pth` in `site-packages/` | All | Primary persistence indicator |
| `sitecustomize.py` in `site-packages/` | All | PRIVCOLLECT credential stealer |
| `cook.py` in `site-packages/` | All | PRIVCOLLECT RCE loader |
| `/tmp/.pc_once_72129118c59f5636c0bb` | Linux/macOS | Credential collection lock file (specific name now confirmed) |
| `/tmp/.pc_once_*` | Linux/macOS | Generic lock file pattern |
| `/tmp/.pc_e_*` | Linux/macOS | OpenSSL temporary staging directories |
| `%TEMP%\.pc_once_*` | Windows | Windows equivalent of Linux lock file |
| `%TEMP%\.pc_e_*` | Windows | Windows equivalent of OpenSSL staging dirs |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Notes |
|--------|-----------|-----|-------|
| Initial Access | Supply Chain Compromise: Compromise Software Dependencies | T1195.001 | Malicious litellm==1.107.0 wheel on PyPI |
| Persistence | Event Triggered Execution: Python path configuration files | T1546.018 | `cook.pth` in site-packages executes on every Python startup |
| Defense Evasion | Obfuscated Files or Information: Encrypted/Encoded File | T1027.013 | AES-256-CBC + RSA-wrapped key encryption of exfiltrated data |
| Defense Evasion | Deobfuscate/Decode Files or Information | T1140 | In-memory decryption of remote stage payload |
| Credential Access | Unsecured Credentials: Private Keys | T1552.004 | Harvest SSH private keys, TLS certificates |
| Credential Access | Unsecured Credentials: Cloud Instance Metadata API | T1552.005 | Harvest cloud IAM credentials (AWS/GCP/Azure) |
| Discovery | System Information Discovery | T1082 | OS/platform fingerprinting for platform-specific payload selection |
| Discovery | System Network Configuration Discovery | T1016 | Network interface and environment enumeration |
| Collection | Data from Local System | T1005 | Credential file collection across cloud providers, browsers, SSH |
| Command and Control | Web Service: Dead Drop Resolver | T1102.001 | GitHub raw content served as pointer to live C2 |
| Command and Control | Ingress Tool Transfer | T1105 | Cook.py downloads and executes hourly remote Python payload |

---

## Microsoft Detection Names

| Name | Component |
|------|-----------|
| `Trojan:PyPI/Stealer.SA` | `sitecustomize.py` — credential stealer component |
| `Trojan:PyPI/LiteLlmSupplyChain.A` | `cook.pth` — Python startup persistence hook |
| `Trojan:PyPI/LiteLlmSupplyChain.B` | `cook.py` — remote code execution loader |
| `Backdoor:PyPI/LiteLlmSupplyChain.C` | Tampered `litellm` wheel package (all variants) |

---

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Delivery |
| Exploitation |
| Installation |
| Command & Control |
| Actions on Objectives |

---

## Attribution

Unknown at time of writing. Microsoft notes the attack infrastructure (AES-256-CBC + RSA key transport, dead-drop resolver via GitHub, lookalike domain registration) is consistent with a financially motivated developer-targeting threat actor. No public attribution to a named group or nation-state.

---

## Recommended Actions

1. **Rotate all credentials** on any system that ran `litellm==1.107.0`, the compromised Docker images, or any Python environment that may have had the malicious wheel transiently installed. Priority: AWS/GCP/Azure IAM keys, SSH private keys, TLS certificates, browser credentials.
2. **Upgrade to `litellm>=1.107.1`** (or pin `1.106.2`).
3. **Manually remove** `cook.pth`, `sitecustomize.py`, and `cook.py` from all `site-packages/` directories. `pip uninstall` of the updated package does NOT remove these files.
4. **Block `litellm[.]dev`** and `www.litellm[.]dev` at DNS/proxy/firewall. The legitimate project domain is `litellm.ai`.
5. **Check for lock artifacts:** `/tmp/.pc_once_72129118c59f5636c0bb`, `/tmp/.pc_once_*`, and `/tmp/.pc_e_*` on Linux/macOS; equivalent temp paths on Windows.
6. **Review Python egress:** Alert on Python processes (`python`, `python3`, interpreter spawns) making outbound HTTP connections outside of expected package registry patterns (PyPI, conda-forge). The dead-drop fetcher uses `raw.githubusercontent.com` in an unusual pattern.
7. **Rebuild Docker containers** from verified base images; do not rely on pulling an updated tag.

---

## References

- [Microsoft Security Blog — Inside the LiteLLM 1.107.0 supply chain compromise (2026-10-23)](https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/)
- [BerriAI GitHub Issue #47826 — Authoritative IOC list](https://github.com/BerriAI/litellm/issues/47826)
- [StepSecurity — litellm 1.107.0 Compromised on PyPI](https://www.stepsecurity.io/blog/litellm-1-107-0-compromised-pypi-backdoored-wheels-credential-stealer)
- [Wiz — LiteLLM Compromised, Steals Credentials](https://www.wiz.io/blog/litellm-compromised-steals-credentials)
- [Datadog Security Labs — LiteLLM supply chain compromise](https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-docker/)
- [MITRE T1546.018 — Event Triggered Execution: Python Path Configuration Files](https://attack.mitre.org/techniques/T1546/018/)
- [MITRE T1102.001 — Web Service: Dead Drop Resolver](https://attack.mitre.org/techniques/T1102/001/)
