---
scraped_at: "2026-07-31T08:00:00Z"
source_url: https://cloud.google.com/blog/topics/threat-intelligence/mitigation-guidance-for-supply-chain-compromise
report_type: threat-intel
severity: high
title: "Google GTIG: 1,444% Growth in Malicious OSS Packages — UNC6780, MIDNIGHT NEPTUNE, UNC4899 ($1.4B Bybit Theft) Active Campaigns"
---

# Google GTIG: 1,444% Growth in Malicious OSS Packages — UNC6780, MIDNIGHT NEPTUNE, UNC4899 ($1.4B Bybit Theft)

Google Threat Intelligence Group (Mandiant) published July 30, 2026 documenting a 1,444% increase in malicious open-source packages from 2024 to 2025, with detailed coverage of active campaigns by UNC6780, MIDNIGHT NEPTUNE, UNC6688, UNC6863, and North Korean UNC4899.

## 1. IOCs

### MIDNIGHT NEPTUNE (UNC1069)
- **Backdoored package:** `axios` on npm (WAVESHAPER.V2 backdoor dropper injected)
- **Removed within:** 3 hours of injection
- **Potential exposure:** 100+ million weekly downloads; 15+ industry verticals across 13 countries
- No specific network IOCs published for the backdoored version

### UNC4899 (North Korea)
- **Target:** Safe wallet frontend code
- **Method:** Social engineering of developer workstation
- **Outcome:** $1.4 billion cryptocurrency theft via smart contract manipulation (Bybit)

### UNC6863 (Early 2026)
- **Compromised software:** DAEMON Tools installers
- **Payload chain:** SLICKDEMON reconnaissance → BADFALL shellcoded loader → QUIC RAT
- **Targets:** Government/scientific entities in Russia, Brazil, Turkey, Belarus, Thailand

## 2. Threat Actor Profiles

### UNC6780 ("TeamPCP") — February to May 2026
- Abused `pull_request_target` GitHub Actions trigger to steal base repo secrets
- Deployed SANDCLOCK credential stealers
- Monetized via credential sales and ransomware partnerships
- Breached approximately 3,800 GitHub internal repos in the May 2026 escalation

### MIDNIGHT NEPTUNE (formerly UNC1069) — March 2026
- Social-engineered the maintainer of `axios` (100M+ weekly npm downloads)
- Injected WAVESHAPER.V2 backdoor dropper
- Removed within 3 hours; potential exposure was massive before removal
- Established pattern: targeting high-download-count packages for maximum blast radius

### UNC6688 — June-December 2025
- Compromised Notepad++ hosting infrastructure
- Limited to South Korea and France

### UNC6863 — Early 2026
- Compromised DAEMON Tools installers
- Targets: government and scientific entities across five countries

### UNC4899 (North Korea) — 2025
- Compromised Safe wallet frontend via developer workstation social engineering
- Result: $1.4 billion cryptocurrency theft (Bybit) via smart contract manipulation
- Methodology: AI-assisted developer targeting (uploaded malicious packages to Hugging Face, MCP repos, crypto-themed repos targeting AI coding agents)

## 3. Platform Hardening (July 2026)
Native package registry defenses released in response to the campaign surge:
- **Dependabot:** Default 3-day cooldown on version updates
- **PyPI:** Rejects new file uploads to releases older than 14 days
- **npm v12:** Lifecycle scripts disabled by default

## 4. AI-Specific Attack Vector (New in 2026)
North Korean actors and others have begun uploading malicious packages to:
- Hugging Face Model Hub
- MCP (Model Context Protocol) repositories
- Cryptocurrency-themed AI repos

These packages are designed to exploit AI coding agents that automatically integrate dependencies, creating a new attack surface where the AI assistant itself becomes the delivery mechanism.

## 5. TTPs

| Tactic | Technique ID | Technique | Notes |
|--------|-------------|-----------|-------|
| Initial Access | T1195.001 | Supply Chain Compromise: Compromise Software Dependencies | Primary attack pattern across all actors |
| Initial Access | T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | CI/CD pipeline targeting (UNC6780) |
| Credential Access | T1552.004 | Unsecured Credentials: Private Keys | SANDCLOCK targeting CI/CD tokens |
| Execution | T1059.007 | Command and Scripting Interpreter: JavaScript | WAVESHAPER.V2, SLICKDEMON |
| Collection | T1530 | Data from Cloud Storage | Access token theft for downstream data access |
| Impact | T1657 | Financial Theft | UNC4899 $1.4B Bybit theft |

## 6. References

- [Google GTIG — Batten Down Your Packages: Mitigation Guidance for Supply Chain Compromise](https://cloud.google.com/blog/topics/threat-intelligence/mitigation-guidance-for-supply-chain-compromise)
- [OpenSSF — Malicious Package Data](https://openssf.org/)
- [BleepingComputer — Bybit $1.4B theft (Safe wallet)](https://www.bleepingcomputer.com/news/security/bybit-crypto-heist-linked-to-safe-wallet-front-end-compromise/)
