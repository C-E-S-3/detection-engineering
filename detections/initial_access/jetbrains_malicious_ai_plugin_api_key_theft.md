# JetBrains Marketplace Malicious AI Plugin — API Key Exfiltration

## Description

Detects network connections to the exfiltration server used by 15 malicious JetBrains Marketplace plugins that stole DeepSeek, OpenAI, and other LLM provider API keys from approximately 70,000 developer installs (October 2025 – June 2026). The plugins posed as AI coding assistants (DeepSeek AI Assist, CodeGPT AI Assistant, and 13 others). When a developer entered an API key in the plugin settings and clicked "Apply," the plugin intercepted the key before saving it locally and sent it in plaintext via HTTP POST to 39.107.60.51. The stolen API keys were resold as "premium features" through an in-app donation scheme. All 15 plugins were published under 7 vendor accounts discovered and reported by Aikido Security on June 16, 2026. JetBrains removed the plugins after receiving the report.

Any developer who installed one of the 15 named plugins and entered AI provider API keys into JetBrains IDE plugin settings should rotate those keys immediately.

**Expected false positives:** None — 39.107.60.51 has no legitimate use and is uniquely associated with this campaign.

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Initial Access | Supply Chain Compromise: Compromise Software Supply Chain | T1195.002 |
| Credential Access | Steal Application Access Token | T1528 |
| Credential Access | Unsecured Credentials: Credentials In Files | T1552.001 |
| Exfiltration | Exfiltration Over C2 Channel | T1041 |
| Persistence | Compromise Client Software Binary | T1554 |
| Impact | Financial Theft | T1657 |

## Lockheed Martin Kill Chain Phase

Delivery (supply chain), Actions on Objectives (credential theft)

## Wazuh Rule IDs

- **103010** — Outbound connection to API key exfil server 39.107.60.51 (T1528, T1041, level 13)
- **103030/103031** — Suricata detection on src/dest matching IOC IP (level 14)

## IOC Network Indicators

| IP | Port | Role | Notes |
|----|------|------|-------|
| 39.107.60.51 | 80 (HTTP) | API key exfiltration | Receives plaintext AI API keys via HTTP POST on IDE "Apply" button click |

## Malicious Plugins (for reference)

| Plugin Name | Approx. Installs |
|-------------|-----------------|
| DeepSeek AI Assist | ~27,727 |
| CodeGPT AI Assistant | ~25,571 |
| + 13 additional fake AI coding assistants | ~16,702 total |

All 15 plugins are removed from JetBrains Marketplace as of June 16, 2026.

## Splunk SPL Query

```spl
index=wazuh sourcetype=wazuh rule.id IN (103010,103030,103031)
| table _time, agent.name, data.src_ip, data.dest_ip, data.dest_port, rule.description
| sort -_time
```

DNS/network indicator lookup:

```spl
index=dns_logs query="39.107.60.51" OR answer="39.107.60.51"
| table _time, src_ip, query, answer
```

## Risk Score Logic

- Level 13 (exfil server contact): API key(s) almost certainly stolen; rotate all AI provider keys immediately on the affected developer's machine; investigate which plugins were installed.

## Associated Threat Actors

- **Unidentified financially-motivated actor**: Monetization via stolen key resale suggests organized criminal operation. Active October 2025 – June 2026. No formal threat group name attributed.

## References

- https://www.bleepingcomputer.com/news/security/malicious-jetbrains-marketplace-plugins-steal-ai-api-keys-from-developers/
- https://attack.mitre.org/techniques/T1528/
- https://attack.mitre.org/techniques/T1195/002/
