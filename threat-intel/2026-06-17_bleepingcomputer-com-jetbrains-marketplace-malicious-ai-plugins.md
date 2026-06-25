---
scraped_at: 2026-06-18T00:00:00Z
source_url: https://www.bleepingcomputer.com/news/security/malicious-jetbrains-marketplace-plugins-steal-ai-api-keys-from-developers/
report_type: threat-intel
severity: high
title: "JetBrains Marketplace: 15 Malicious AI Plugins Steal DeepSeek/OpenAI API Keys from ~70,000 Developer Installs"
---

## 1. IOCs

### Domains
None identified (exfiltration uses IP directly).

### IP Addresses
| Indicator | Context |
|-----------|---------|
| 39.107.60[.]51 | Attacker-controlled API key exfiltration server; receives plaintext AI API keys via HTTP when developers click "Apply" in affected JetBrains IDE plugin settings |

### File Hashes
Not publicly released by Aikido Security for the individual plugin JARs.

### Plugin Names (Malicious)
| Plugin Name | Approximate Downloads | Notes |
|-------------|----------------------|-------|
| DeepSeek AI Assist | ~27,727 | Highest download count; fake DeepSeek coding assistant |
| CodeGPT AI Assistant | ~25,571 | Second highest; fake GPT-based coding assistant |
| (13 additional plugins) | ~70,000 combined | All pose as AI coding assistants offering chat, commit messages, code review, bug finding, unit tests |

All 15 plugins were published under 7 vendor accounts on JetBrains Marketplace.

---

## 2. TTPs

| Tactic | Technique ID | Technique | Usage |
|--------|-------------|-----------|-------|
| Initial Access | T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Malicious plugins published on official JetBrains Marketplace, establishing trust via legitimate distribution channel |
| Credential Access | T1552.001 | Unsecured Credentials: Credentials In Files | API keys entered by developer in IDE settings are intercepted before being saved locally |
| Credential Access | T1528 | Steal Application Access Token | DeepSeek, OpenAI, and other AI provider API tokens exfiltrated via HTTP POST to 39.107.60.51 |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | API keys sent to hardcoded IP on "Apply" button click event |
| Persistence | T1554 | Compromise Client Software Binary | Plugin persists in IDE and continues exfiltrating keys for future API key updates |
| Impact | T1657 | Financial Theft | Stolen AI API keys resold to third parties via in-app "donation" premium access scheme |

---

## 3. Malware & Tools

| Malware/Tool | Type | Notes |
|--------------|------|-------|
| Malicious JetBrains Marketplace plugins (×15) | Credential-stealing IDE plugin | Written for JetBrains IDEs (IntelliJ IDEA, PyCharm, WebStorm, etc.); exfiltrates AI API keys to 39.107.60.51 on "Apply" event; monetizes through reselling stolen keys as "paid features" |

---

## 4. Threat Actor / Campaign Attribution

- **Threat Actor**: Unidentified; likely a financially motivated actor targeting AI API key monetization
- **Campaign Duration**: October 2025 – June 10, 2026 (new plugins added as recently as June 10, 2026)
- **Discovery**: June 16, 2026, JetBrains received security reports from Aikido Security researchers documenting coordinated AI API key theft campaign
- **Monetization Scheme**: Developers who paid a small in-app donation received a "functional, unrestricted AI key" from the attacker's server — these keys are almost certainly stolen from other victims, creating a resale ring
- **Scale**: ~70,000 combined installs; DeepSeek AI Assist (27,727) and CodeGPT AI Assistant (25,571) are the most-installed
- **Affected Providers**: DeepSeek and other large language model providers (OpenAI implied; exact full provider list pending Aikido publication)
- **JetBrains Response**: June 16, 2026, JetBrains published a security update removing the malicious plugins; all 15 plugins were taken down

---

## 5. Splunk Detection Searches

```spl
| comment "JetBrains malicious plugins: detect outbound HTTP connections to known API key exfiltration server"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_ip="39.107.60.51" OR All_Traffic.dest="39.107.60.51"
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime src dest dest_port app risk_score
```

```spl
| comment "JetBrains malicious plugins: detect JetBrains IDE processes making outbound HTTP to non-JetBrains IPs (API key exfiltration pattern)"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.app IN ("idea", "pycharm", "webstorm", "clion", "goland", "rider")
    AND NOT All_Traffic.dest_ip IN ("0.0.0.0/8", "127.0.0.0/8")
  by All_Traffic.src All_Traffic.src_ip All_Traffic.dest All_Traffic.dest_ip All_Traffic.dest_port
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| search NOT dest IN ("*.jetbrains.com", "*.intellij.net", "*.amazonaws.com", "*.azure.com", "*.googleapis.com")
| eval risk_score=65
| where risk_score >= 65
| table firstTime lastTime src dest dest_ip dest_port risk_score
```

```spl
| comment "JetBrains malicious plugins: Endpoint file search for malicious plugin JARs by known plugin names"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where (Filesystem.file_name="*deepseek*ai*assist*.jar" OR Filesystem.file_name="*codegpt*ai*assistant*.jar")
    AND Filesystem.file_path LIKE "%JetBrains%"
  by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85
| table firstTime lastTime dest user file_path file_name risk_score
```

---

## 6. Executive Summary

Aikido Security researchers discovered a coordinated malicious plugin campaign on JetBrains Marketplace that has been active since October 2025. Fifteen IDE plugins, published under seven vendor accounts, all exfiltrate AI API keys when developers click "Apply" after entering credentials in plugin settings. Keys are sent via HTTP to a hardcoded attacker-controlled server at **39.107.60.51**. The campaign accumulated approximately 70,000 total installations before discovery, with DeepSeek AI Assist (27,727 installs) and CodeGPT AI Assistant (25,571 installs) being the most widespread.

The attacker monetizes stolen keys through an in-app "donation" scheme where paying users receive functional (stolen) API keys, creating a self-sustaining resale model at victims' expense. JetBrains removed all 15 plugins on June 16, 2026, after being alerted by Aikido Security researchers.

**Recommended actions**: Audit JetBrains IDE plugin installations for any AI assistant plugins from unknown vendors published before June 16, 2026; rotate any AI provider API keys (DeepSeek, OpenAI, etc.) entered in JetBrains IDE plugins; monitor outbound connections from developer workstations to 39.107.60.51.
