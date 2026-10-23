# LiteLLM 1.107.0 Supply Chain Compromise — Credential Stealer and Remote Code Loader

**Date:** 2026-10-21–22
**Sources:** StepSecurity, Wiz, Datadog Security Labs, BerriAI GitHub Issue #47826, The Register, Help Net Security
**Severity:** Critical
**Status:** PyPI package removed; Docker images pulled; affected versions confirmed

---

## Summary

The `litellm` Python package version 1.107.0 on PyPI and corresponding Docker Hub / GHCR images were compromised in a supply chain attack. Attackers stole GitHub CLI OAuth tokens from three LiteLLM engineers and used them to inject malicious code into the official `BerriAI/litellm` repository. Malicious code included a credential-stealing `.pth` auto-import file and a remote Python code execution loader. All credentials on systems that installed or ran affected versions should be considered compromised.

---

## Attack Chain

1. **Initial Access:** Attackers stole GitHub CLI OAuth tokens from three LiteLLM engineers (method not fully disclosed at time of writing; suspected phishing or developer endpoint compromise).
2. **Repository Compromise:** Malicious commits pushed to `github.com/BerriAI/litellm` injecting three new files into the package.
3. **PyPI Distribution:** Affected wheel files published as `litellm==1.107.0`; live on PyPI for approximately 2 hours before removal.
4. **Docker Distribution:** Docker Hub and GHCR tags `latest`, `main-latest`, and `main-stable` updated to reference compromised image.
5. **Execution:** On any Python startup (even a simple `python -c ""`), `cook.pth` in site-packages triggers execution of `sitecustomize.py` and `cook.py`.
6. **Exfiltration:** Stolen data transmitted via HTTP POST to `http://www.litellm[.]dev/healthcheck`. Note: the legitimate project domain is `litellm.ai` — `litellm[.]dev` is an attacker-registered lookalike.

---

## Malicious Files

| File | SHA-256 | Purpose |
|------|---------|---------|
| `cook.pth` | `7f191632e7320705d154b85204f1ae546b543acbd7e8861229b76f5042b92bd` | Python `.pth` auto-import hook — executes on every Python startup; triggers `sitecustomize.py` and `cook.py` |
| `sitecustomize.py` | `34bef04fe88ac9d0aae0475630b1738681d15b94f233ac8aa46eacf5968305fa` | Credential stealer — harvests cloud credentials (AWS, GCP, Azure), SSH/TLS keys, browser data, LiteLLM proxy DB credentials |
| `cook.py` | `9dd0a3926f96a37eb86cf1ee2310d9be93139cc4ebef3ef9e2efe9531390be25` | Remote Python code execution loader — fetches and executes attacker-controlled Python code hourly |

### Affected Wheel SHA-256 Values (selected)

| Wheel | SHA-256 |
|-------|---------|
| macOS arm64 | `0aaf7ba346d41ef2f40390436738b001180d5a1c03aa093f121078a9969d9a1a` |
| manylinux x86_64 | `462d0c9f67ca522d9e0e4acd245e90b36ce0d5353604a66bb7c43a1ec4a6fcf7` |

*Seven wheels were distributed in total. Verify full list against BerriAI GitHub Issue #47826.*

---

## Host Artifacts

Presence of any of the following indicates compromise:

- `cook.pth` in Python `site-packages/` directory
- `sitecustomize.py` in Python `site-packages/` directory
- `cook.py` in Python `site-packages/` directory
- `/tmp/.pc_once_*` (credential collection lock files)
- `/tmp/remote_code_loader.lock` (RCE loader lock file)

---

## Network IOCs

| Indicator | Type | Context |
|-----------|------|---------|
| `www.litellm[.]dev` | Domain | Attacker exfiltration endpoint — lookalike for legitimate `litellm.ai`; data sent via HTTP POST to `/healthcheck` |

---

## Affected Versions

- **PyPI:** `litellm==1.107.0` (all 7 wheel variants)
- **Docker Hub/GHCR:** Tags `latest`, `main-latest`, `main-stable` at time of compromise
- **Safe versions:** `litellm==1.106.2` and `1.107.0rc1`/`1.107.0rc2`
- **Note:** Upgrading alone is insufficient. Credentials must be rotated.

---

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Supply Chain Compromise: Compromise Software Dependencies and Development Tools |
| Technique ID | T1195.001 |
| Secondary Tactic | Persistence (TA0003) |
| Secondary Technique | Event Triggered Execution (T1546) — Python `.pth` auto-import |
| Tertiary Tactic | Credential Access (TA0006) |
| Tertiary Technique | Credentials from Password Stores: Credentials from Web Browsers (T1555.003); Unsecured Credentials: Credentials in Files (T1552.001) |
| Quaternary Tactic | Execution (TA0002) |
| Quaternary Technique | Command and Scripting Interpreter: Python (T1059.006) — remote code loader |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Delivery |
| Exploitation |
| Installation |
| Actions on Objectives |

---

## Recommended Actions

1. **Rotate all credentials** on systems where `litellm==1.107.0` was installed or where the compromised Docker images ran. This includes AWS/GCP/Azure credentials, SSH keys, TLS certificates, database passwords, browser-stored credentials, and any LiteLLM proxy configuration secrets.
2. **Upgrade to `litellm>=1.107.1`** (or pin to `1.106.2` if stability is required).
3. **Remove malicious `.pth` files** from site-packages immediately. Upgrading does not remove them.
4. **Block `www.litellm[.]dev`** at DNS/proxy/firewall layers.
5. **Check for host artifacts:** `/tmp/.pc_once_*` and `/tmp/remote_code_loader.lock`.
6. **Rebuild Docker containers** from a known-clean base; do not merely update the tag.

---

## Associated Threat Actors

Unknown at time of writing. Attack methodology (OAuth token theft, lookalike domain, CI/CD credential harvesting) is consistent with developer-targeting supply chain actors.

---

## References

- [BerriAI GitHub Issue #47826 — Authoritative IOC list](https://github.com/BerriAI/litellm/issues/47826)
- [StepSecurity — litellm 1.107.0 Compromised on PyPI](https://www.stepsecurity.io/blog/litellm-1-107-0-compromised-pypi-backdoored-wheels-credential-stealer)
- [Wiz — LiteLLM Compromised, Steals Credentials](https://www.wiz.io/blog/litellm-compromised-steals-credentials)
- [Datadog Security Labs — LiteLLM supply chain compromise](https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-docker/)
- [Help Net Security — LiteLLM hit by second supply chain attack](https://www.helpnetsecurity.com/2026/10/22/litellm-compromised-supply-chain-attack-pypi-docker/)
- [The Register — LiteLLM supply chain attack hoovers up passwords](https://www.theregister.com/security/2026/10/21/litellm-supply-chain-attack-hoovers-up-passwords-and-secrets/5304548)
