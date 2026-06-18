---
scraped_at: 2026-06-18T00:00:00Z
source_url: https://cloud.google.com/blog/topics/threat-intelligence/prc-targets-us-medical-research
report_type: threat-intel
severity: critical
title: "UNC6508 / INFINITERED: China-Nexus APT Conducts 26-Month Undetected Espionage Against US/Canadian Medical and Defense Research via REDCap"
---

## 1. IOCs

### IP Addresses
| Indicator | Context |
|-----------|---------|
| 23.169.65.49 | Compromised ASUS router used by UNC6508 as a hop point for FortiSandbox admin login; not an attacker-controlled C2 but an intermediate pivot node |

### File Hashes (SHA256)
| Hash | Type | Description |
|------|------|-------------|
| ba6b73b0ca0dc7f86b3b397893ac32d729fd53f9df20643288f141f29d020af7 | SHA256 | INFINITERED help.php persistence module — web shell injected into REDCap application that reinjects malicious code into every upgrade |
| db65c1b9f9e4cb4d729f45ad4b6fcf3e277caf9eb4c875425dec93fd883f9136 | SHA256 | INFINITERED credential harvester module — captures login POST request data and stores AES-encrypted in database |
| c1ac43d23f89d41eb4ff131678ab562ab2cfed9aa334b13767ef141d303b0e5b | SHA256 | INFINITERED credential harvester variant |
| 8f0158855a656b629ca76ebca565f18bc25563ded34b65d6771632c20edb68ec | SHA256 | INFINITERED backdoor module — HTTP Cookie C2 using REDCAP-TOKEN parameter; supports OS command execution, file upload/download, SQL query execution |
| 51a57bfc9ed3eb6451c1c289607814d59e1698c666fb97ac5f694c398f23d045 | SHA256 | INFINITERED dropper stage 1 |
| 4efbef69eb3b09bacff892d6a55778d07c418e7f15eba3cf1245e8cdfd8dda0b | SHA256 | INFINITERED dropper stage 2 |
| 58bb25777e0aa86bcd2125101e0bca4e8732b03d91bd8d2f205b446a2a8d5c86 | SHA256 | INFINITERED dropper stage 3 |

### Email Exfiltration Infrastructure
| Indicator | Context |
|-----------|---------|
| BebitaBarefoot774@gmail.com | Attacker-controlled Gmail account used as BCC destination for "Patroit" content compliance rule exfiltration |

### INFINITERED Host Indicators
| Indicator | Description |
|-----------|-------------|
| b49e334d-9c01-463e-9bc5-00a6920fb66e | INFINITERED GUID delimiter injected into REDCap upgrade packages |
| xc32038474a | INFINITERED REDCap database session ID prefix used by backdoor C2 protocol |

---

## 2. TTPs

| Tactic | Technique ID | Technique | Usage |
|--------|-------------|-----------|-------|
| Initial Access | T1190 | Exploit Public-Facing Application | REDCap web server exploitation (exact vulnerability not specified; attacker exploited externally accessible legacy REDCap instances) |
| Persistence | T1505.003 | Server Software Component: Web Shell | INFINITERED help.php injected into REDCap application; reinjects itself into every REDCap upgrade package (upgrade interception) |
| Persistence | T1554 | Compromise Client Software Binary | INFINITERED intercepts REDCap upgrade packages and reinjects malicious code — patching does not clear infection |
| Credential Access | T1056.003 | Input Capture: Web Portal Capture | INFINITERED credential harvester captures username/password from POST requests during REDCap login |
| Credential Access | T1555 | Credentials from Password Stores | Stored encrypted credentials retrieved via backdoor C2 command 03 |
| Collection | T1114.003 | Email Collection: Email Forwarding Rule | "Patroit" Gmail content compliance rule BCCs matching emails to BebitaBarefoot774@gmail.com; novel technique for China-nexus actors |
| Collection | T1213 | Data from Information Repositories | Arbitrary SQL execution via INFINITERED backdoor command 05 enables direct REDCap database queries |
| Defense Evasion | T1090.003 | Proxy: Multi-hop Proxy | Routing through compromised IoT devices, residential proxies, and US-only VPS (OBF networks) to blend with legitimate US traffic |
| Defense Evasion | T1027 | Obfuscated Files or Information | INFINITERED backdoor communicates via HTTP Cookie REDCAP-TOKEN header to blend with legitimate REDCap sessions |
| Defense Evasion | T1562.001 | Impair Defenses: Disable or Modify Tools | Silent BCC compliance rule creates invisible email exfiltration channel without modifying email headers |
| Defense Evasion | T1689 | Downgrade Attack | Attacker performs REDCap version downgrade attacks via upgrade interception mechanism |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | INFINITERED backdoor C2 via HTTP Cookie REDCAP-TOKEN; empty payload = beacon; command codes 00 (exec), 02 (upload), 03 (get credentials), 04 (delete credentials), 05 (SQL), ej671a16i7fd8202nu6ltfg5p6x7u (download) |
| Exfiltration | T1567 | Exfiltration Over Web Service | Credentials exfiltrated via Gmail content compliance rule (SMTP via Google infrastructure) |

---

## 3. Malware & Tools

| Malware | Type | Notes |
|---------|------|-------|
| INFINITERED | Multi-component REDCap-specific implant | Three modules: (1) Persistence/upgrade interception (help.php); (2) Credential harvester (AES-encrypted credential storage); (3) Backdoor (HTTP Cookie REDCAP-TOKEN C2 with 7 command codes including OS exec, SQL, file operations); first documented REDCap-specific implant; compiled .NET, confirmed compilation date Jan 13, 2026; ConfuserEx obfuscated |

---

## 4. Threat Actor / Campaign Attribution

- **Threat Actor**: UNC6508 — PRC-nexus threat actor
- **Attribution**: High confidence PRC state-sponsored espionage; targeting priorities (AI research, cyber offensive programs, uncrewed vehicles, military health, molecular biology, clinical trials, military readiness) align with known PRC strategic intelligence collection objectives; use of US-only OBF networks is consistent with PRC operational security tradecraft
- **Campaign Duration**: September 2023 (earliest compromise) – November 2025 (latest confirmed activity); 26+ months undetected
- **INFINITERED Deployment**: December 2023 (3 months after initial access)
- **Targets**:
  - World-renowned clinical providers
  - Premier academic medical centers in North America (US and Canada)
  - Military health institutions (Indo-Pacific command focus)
  - Professional advocacy groups
  - Health regulatory bodies
  - AI research (including military AI), cyber offensive research, uncrewed vehicle systems, military readiness research
- **Novel Technique**: First documented use by a China-nexus actor of Google Workspace "content compliance rules" for covert email exfiltration — the "Patroit" rule silently BCCs matching emails without leaving sender-visible traces
- **Persistence Mechanism**: INFINITERED's upgrade interception is particularly sophisticated: the malware hooks REDCap's update mechanism so that patching/upgrading REDCap does not remove the infection — only complete reinstallation would clear it

---

## 5. Splunk Detection Searches

```spl
| comment "UNC6508/INFINITERED: detect INFINITERED file hash presence on web servers"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_hash IN (
    "ba6b73b0ca0dc7f86b3b397893ac32d729fd53f9df20643288f141f29d020af7",
    "db65c1b9f9e4cb4d729f45ad4b6fcf3e277caf9eb4c875425dec93fd883f9136",
    "c1ac43d23f89d41eb4ff131678ab562ab2cfed9aa334b13767ef141d303b0e5b",
    "8f0158855a656b629ca76ebca565f18bc25563ded34b65d6771632c20edb68ec",
    "51a57bfc9ed3eb6451c1c289607814d59e1698c666fb97ac5f694c398f23d045",
    "4efbef69eb3b09bacff892d6a55778d07c418e7f15eba3cf1245e8cdfd8dda0b",
    "58bb25777e0aa86bcd2125101e0bca4e8732b03d91bd8d2f205b446a2a8d5c86")
  by Filesystem.dest Filesystem.file_name Filesystem.file_path Filesystem.file_hash Filesystem.user
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=100
| table firstTime lastTime dest file_name file_path file_hash user risk_score
```

```spl
| comment "UNC6508/INFINITERED: detect anomalous web shell activity on REDCap — web server processes spawning OS children"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN ("apache2", "httpd", "nginx", "php", "php-fpm", "php8", "php7")
    AND Processes.process_name IN ("bash", "sh", "dash", "id", "whoami", "wget", "curl", "nc", "ncat", "python", "python3", "perl", "ruby")
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85
| where risk_score >= 85
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| comment "UNC6508/INFINITERED: detect INFINITERED C2 indicator — HTTP requests containing REDCAP-TOKEN cookie with INFINITERED session prefix"
`web`
| search http_method=GET OR http_method=POST
| rex field=cookie "REDCAP-TOKEN=(?<redcap_token>[^;]+)"
| where isnotnull(redcap_token)
| search redcap_token="xc32038474a*"
| eval risk_score=95
| `security_content_ctime(_time)`
| table _time src dest uri redcap_token risk_score
```

```spl
| comment "UNC6508/INFINITERED: detect Patroit compliance rule exfiltration — outbound SMTP containing 'Patroit' in rule name or BCC to attacker Gmail"
`o365`
| search Operation=New-TransportRule OR Operation=Set-TransportRule
| eval rule_name=mvindex(Parameters{}.Value, 0)
| search rule_name="Patroit" OR Description="*Patroit*"
| eval risk_score=95
| `security_content_ctime(_time)`
| table _time UserId Operation rule_name ClientIP risk_score
```

---

## 6. Executive Summary

Google Threat Intelligence Group (GTIG) / Mandiant disclosed on June 15, 2026, that China-nexus threat actor UNC6508 maintained undetected access to at least one North American medical research organization for over 26 months (September 2023 – November 2025). The actor exploited externally-accessible REDCap research database servers, deploying a sophisticated REDCap-specific implant called **INFINITERED** — the first documented malware designed specifically to persist through REDCap software upgrades.

INFINITERED consists of three coordinated modules: a persistence layer that injects malicious code into every REDCap upgrade package (preventing patch-based remediation), an AES-encrypted credential harvester, and a backdoor that communicates via HTTP Cookie headers (REDCAP-TOKEN parameter). Notably, UNC6508 used a Google Workspace "content compliance rule" named "Patroit" to silently BCC matching emails to an attacker-controlled Gmail account — a novel exfiltration technique not previously observed in China-nexus campaigns.

Targeted entities include clinical providers, academic medical centers, military health institutions, and AI/defense research organizations in the US and Canada. Intelligence collection focused on AI, cyber offensive programs, uncrewed vehicles, military readiness, molecular discovery, clinical trials, and public health policy — all priority collection areas for PRC strategic interests.

**Recommended actions**: Scan all REDCap-hosted systems for INFINITERED file hashes; audit Google Workspace content compliance rules for unauthorized entries (particularly "Patroit"); review web server process trees for anomalous child processes from PHP/httpd parents; complete reinstallation (not just patching) of any suspected INFINITERED-infected REDCap instance.
