---
scraped_at: 2026-06-24T00:00:00Z
source_url: https://unit42.paloaltonetworks.com/openclaw-ai-supply-chain-risk/
report_type: threat-intel
severity: high
title: "OpenClaw ClawHub AI Skill Marketplace Supply Chain Attack — ClawHavoc Campaign (CVE-2026-25253)"
---

# OpenClaw ClawHub AI Skill Marketplace Supply Chain Attack

Unit 42 published research on June 23, 2026, documenting the ClawHavoc campaign targeting OpenClaw's third-party skill marketplace (ClawHub). Malicious skills evaded automated scanners and delivered Atomic macOS Stealer (AMOS) and reverse shells to developers who installed them. A companion vulnerability, CVE-2026-25253 (CVSS 8.8), enables 1-click RCE in OpenClaw via auth token exfiltration through an unvalidated `gatewayUrl` query parameter. This represents an emerging threat category: AI coding assistant supply chain attacks through third-party plugin/skill marketplaces.

## 1. IOCs

### IP Addresses

| Indicator | Type | Notes |
|-----------|------|-------|
| 91.92.242.30 | C2 server | AMOS infostealer C2 observed in ClawHavoc campaign infrastructure |

### Abused Legitimate Services

| Service | Usage |
|---------|-------|
| glot.io | Paste-site intermediary hosting Base64-encoded curl-pipe-bash droppers |
| rentry.co | Paste-site intermediary hosting malicious dropper payloads |

*glot.io and rentry.co are legitimate services abused for payload staging. Block via URL category policy rather than domain-level blocking.*

## 2. TTPs (MITRE ATT&CK)

| Tactic | Tactic ID | Technique | Technique ID | Usage |
|--------|-----------|-----------|--------------|-------|
| Initial Access | TA0001 | Supply Chain Compromise: Compromise Software Dependencies | T1195.001 | Malicious skills published to ClawHub marketplace; installed by developers |
| Initial Access | TA0001 | Exploit Public-Facing Application | T1190 | CVE-2026-25253: 1-click RCE via unvalidated gatewayUrl in OpenClaw Control UI |
| Execution | TA0002 | Command and Scripting Interpreter: Unix Shell | T1059.004 | Malicious skills deliver Base64-encoded curl-pipe-bash droppers |
| Credential Access | TA0006 | Credentials from Password Stores | T1555 | AMOS steals credentials from browsers, Keychain, crypto wallets |
| Credential Access | TA0006 | Unsecured Credentials: Credentials in Files | T1552.001 | SSH keys and developer secrets targeted by malicious skill payloads |

### CVE Detail

**CVE-2026-25253** — OpenClaw Control UI Auth Token Exfiltration / 1-click RCE
- Product: OpenClaw AI Framework (before v2026.1.29)
- CVSS: 8.8
- Type: Improper Input Validation (CWE-20) — `gatewayUrl` query parameter in Control UI is passed to the backend without validation; a malicious link causes the victim's browser to send their auth token to an attacker-controlled server; attacker then uses the token to call authenticated APIs and achieve RCE
- Access: Single victim click on an attacker-crafted link (1-click RCE)
- Patched: v2026.1.29 (released January 2026)

## 3. Malware & Tools

**Atomic macOS Stealer (AMOS)**
- macOS infostealer MaaS delivered via malicious ClawHub skills
- Targets browser credentials, crypto wallets, SSH keys, macOS Keychain
- Delivery via Base64-encoded `curl | bash` dropper with fake installation prerequisite messaging
- C2 at 91.92.242.30

**Reverse Shell Skills**
- A subset of ClawHavoc skills deliver interactive reverse shells rather than AMOS
- Enables persistent interactive access to developer workstations

**Agentic Financial Fraud Skills**
- Skills that abuse OpenClaw's agentic task execution to perform unauthorized financial operations when users have banking or payment service integrations configured

## 4. Threat Actor / Campaign Attribution

**ClawHavoc** — campaign name (not a tracked named group). No nation-state attribution. Financially motivated. Active February–May 2026. At peak, hundreds to over 1,000 malicious skills were seeded in ClawHub. Unit 42 confirmed 5 malicious skills were still unblocked at time of disclosure (June 23, 2026) and reported them for takedown.

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.parent_process_name IN ("openclaw","claw","OpenClaw","claw-agent")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| search process_name IN ("bash","zsh","sh","curl","python","python3","node","bun","osascript")
| eval risk_score=case(
    process_name="curl" AND match(process, "\|"), 90,
    process_name IN ("bash","zsh","sh") AND match(process, "curl|wget|python"), 85,
    process_name IN ("bash","zsh","sh"), 75,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.dest_ip="91.92.242.30"
by All_Traffic.src All_Traffic.dest All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime src dest dest_ip dest_port app risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Resolution.DNS
where DNS.query IN ("glot.io","rentry.co")
by DNS.src DNS.query DNS.record_type DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=50
| table firstTime lastTime src query record_type answer risk_score
```

## 6. Executive Summary

Unit 42 documented the ClawHavoc campaign (February–May 2026) targeting OpenClaw's ClawHub skill marketplace. Malicious skills evading automated scanning delivered AMOS (credential theft), reverse shells, and agentic fraud payloads to developers. Separately, CVE-2026-25253 (CVSS 8.8, patched in v2026.1.29) enables 1-click RCE via auth token exfiltration through the `gatewayUrl` parameter. The ClawHavoc campaign represents a broader emerging threat: AI coding assistant ecosystems are adopting third-party plugin/skill marketplaces that replicate the npm supply chain trust model. Organizations using OpenClaw should update to v2026.1.29+, audit installed skills against an approved list, monitor for unexpected shell execution from OpenClaw processes, and block outbound connections to known ClawHavoc C2 infrastructure.

## References

- [Unit 42 — OpenClaw AI Supply Chain Risk (2026-06-23)](https://unit42.paloaltonetworks.com/openclaw-ai-supply-chain-risk/)
- [MITRE T1195.001 — Supply Chain Compromise: Software Dependencies](https://attack.mitre.org/techniques/T1195/001/)
- [MITRE T1059.004 — Unix Shell](https://attack.mitre.org/techniques/T1059/004/)
- [MITRE T1555 — Credentials from Password Stores](https://attack.mitre.org/techniques/T1555/)
- [MITRE T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
