---
scraped_at: "2026-07-06T00:00:00Z"
source_url: https://www.sysdig.com/blog/jadepuffer-agentic-ransomware-for-automated-database-extortion
report_type: threat-intel
severity: high
title: "JadePuffer: First Documented Agentic Threat Actor Ransomware Targeting Langflow and Nacos"
---

# JadePuffer: First Documented Agentic Threat Actor Ransomware Targeting Langflow and Nacos

## 1. IOCs

### Network

| Indicator | Type | Notes |
|-----------|------|-------|
| `45.131.66[.]106` | IPv4 | C2 beacon; HTTP POST to port 4444 `/beacon` every 30 minutes |

### Cryptocurrency / Extortion Contact

| Indicator | Type | Notes |
|-----------|------|-------|
| `3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy` | Bitcoin address | Ransom payment address in `README_RANSOM` MySQL table |
| `e78393397[@]proton[.]me` | Email | Attacker contact address in ransom note |

No file hashes were published. The attack executed entirely within the Python and MySQL runtime environments and did not drop traditional PE/ELF binaries to disk.

### CVEs Exploited

| CVE | Description | CVSS | Status |
|-----|-------------|------|--------|
| CVE-2025-3248 | Langflow unauthenticated RCE — missing authentication on `/api/v1/validate/code` endpoint; arbitrary Python execution without credentials | 9.8 | Fixed in Langflow 1.3.0; CISA KEV (May 2025) |
| CVE-2021-29441 | Nacos authentication bypass — allows unauthenticated creation of administrator accounts via the User Center API | 9.8 | Patched; older known vulnerability |

---

## 2. TTPs

| Tactic | Tactic ID | Technique | Technique ID | Usage |
|--------|-----------|-----------|--------------|-------|
| Initial Access | TA0001 | Exploit Public-Facing Application | T1190 | CVE-2025-3248 — HTTP POST to Langflow `/api/v1/validate/code` without authentication; arbitrary Python executes server-side |
| Credential Access | TA0006 | Unsecured Credentials: Credentials in Files | T1552.001 | Swept Langflow environment for API keys (OpenAI, Anthropic, DeepSeek, Gemini) and cloud credentials (AWS, GCP, Azure, Alibaba, Tencent, Huawei); cryptocurrency wallet keys and seed phrases |
| Credential Access | TA0006 | Valid Accounts | T1078 | Exploited CVE-2021-29441 to create rogue Nacos administrator account; used MinIO default credentials for storage access |
| Execution | TA0002 | Command and Scripting Interpreter: Python | T1059.006 | Arbitrary Python submitted via Langflow API executes within the Langflow process; lateral pivot to Nacos and MySQL performed from this Python context |
| Persistence | TA0003 | Scheduled Task/Job: Cron | T1053.003 | Crontab entry installed on the Langflow host for persistent re-access; C2 beacon to `45.131.66[.]106:4444/beacon` every 30 minutes |
| Impact | TA0040 | Data Encrypted for Impact | T1486 | 1,342 Nacos service configuration items encrypted in-place using MySQL native `AES_ENCRYPT()` function; encryption key derived from two concatenated UUID4 values printed once to stdout and discarded — recovery is impossible even with payment |
| Impact | TA0040 | Data Destruction | T1485 | Original Nacos `config_info` and config history tables dropped after encryption; `README_RANSOM` extortion table created in their place |
| Impact | TA0040 | Resource Hijacking | T1496 | AI API keys enumerated and exfiltrated; potential for billing-based financial harm against victim's AI provider accounts |

---

## 3. Malware & Tools

### JadePuffer (Agentic Ransomware)

- **Type:** Agentic Threat Actor (ATA) — fully autonomous LLM-driven attack execution
- **Initial Access:** CVE-2025-3248 on internet-exposed Langflow instance
- **Autonomy:** All attack phases executed without observed human-in-the-loop intervention; failed login attempts retried with corrected parameters in as little as 31 seconds
- **Encryption Method:** MySQL native `AES_ENCRYPT()` (AES-128-ECB despite ransom note claiming AES-256); encryption key discarded after single stdout print — inherently unrecoverable
- **Ransom Delivery:** MySQL table `README_RANSOM` inserted into the victim database (no dropped text file)
- **Kill Chain:**
  1. CVE-2025-3248 → code execution in Langflow Python process
  2. Parallel credential sweep: AI API keys, cloud provider credentials, wallet keys
  3. Nacos pivot via CVE-2021-29441 admin creation + MinIO default credentials
  4. MySQL encryption of all Nacos config data
  5. Table destruction + ransom table creation
  6. Crontab persistence + C2 beacon installed
- **Notable:** Agent operated fully autonomously; LLM backend not publicly disclosed by Sysdig

---

## 4. Threat Actor / Campaign Attribution

| Attribute | Value |
|-----------|-------|
| Name | JadePuffer (Sysdig tracking designation) |
| Type | Agentic Threat Actor (ATA) — first documented ransomware campaign operated by an autonomous LLM agent |
| Attribution | Unknown; LLM backend not disclosed |
| Motivation | Financial — ransom payment for decryption key |
| Target Profile | Organizations running internet-exposed Langflow instances connected to production infrastructure (Nacos service mesh, MySQL databases, cloud APIs) |
| First Documented | July 4, 2026 (Sysdig disclosure) |
| Significance | First documented case of an autonomous AI agent completing a full ransomware kill chain — initial access, credential harvesting, lateral movement, encryption, and persistence — without human operator intervention |

---

## 5. Splunk Detection Searches

### Search 1 — Python Web Framework Spawning OS Commands (Langflow RCE)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN ("python.exe","python3","python","gunicorn","uvicorn","langflow")
    AND Processes.process_name IN ("sh","bash","zsh","cmd.exe","powershell.exe","csh","dash","ksh")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=100
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

Detects Python web application processes (Langflow, gunicorn, uvicorn) spawning OS shell children — the execution pattern from CVE-2025-3248 and similar Python RCE vulnerabilities in Jupyter, FastAPI, and other AI frameworks.

### Search 2 — Crontab Modification Following Python Web App Execution

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name="crontab"
    AND Processes.parent_process_name IN ("python3","python","sh","bash","gunicorn","uvicorn")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

Detects crontab modification by processes descended from Python web application servers — the persistence mechanism JadePuffer installs after gaining code execution via Langflow.

### Search 3 — Database-Native Encryption Commands (Ransomware IOC)

```spl
`mysql_audit`
| regex _raw="(?i)AES_ENCRYPT\s*\("
| stats count as aes_encrypt_calls, dc(table_name) as tables_affected, earliest(_time) as firstTime, latest(_time) as lastTime
  by host, user
| where aes_encrypt_calls >= 50
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(aes_encrypt_calls >= 500, 95, aes_encrypt_calls >= 100, 80, 1=1, 65)
| where risk_score >= 65
| table firstTime lastTime host user aes_encrypt_calls tables_affected risk_score
```

Detects bulk use of MySQL's `AES_ENCRYPT()` function — the in-database encryption mechanism JadePuffer used to encrypt 1,342 Nacos configuration items. Legitimate administrative use of `AES_ENCRYPT` at this scale is extremely rare. Requires MySQL general/audit log forwarding to Splunk.

### Search 4 — Nacos Admin User Creation (CVE-2021-29441)

```spl
`nacos`
| rex field=_raw "\"method\":\"(?P<http_method>[A-Z]+)\".*\"url\":\"(?P<url_path>[^\"]+)\".*\"status\":(?P<status_code>\d+)"
| where http_method="POST" AND match(url_path, "(?i)/nacos/v1/auth/users") AND status_code=200
| stats count, values(src_ip) as src_ips, dc(src_ip) as src_count by dest, url_path, _time span=5m
| where count >= 1
| eval risk_score=if(src_count > 1, 90, 75)
| table _time dest src_ips url_path count risk_score
```

Detects successful user creation via Nacos unauthenticated admin endpoint exploited by CVE-2021-29441. Legitimate Nacos admin user creation is low-frequency; any POST to `/nacos/v1/auth/users` with a 200 response warrants investigation. Requires Nacos access logs forwarded to Splunk.

---

## 6. Executive Summary

Sysdig disclosed **JadePuffer** on July 4, 2026 — the first documented ransomware operation conducted entirely by an autonomous LLM agent (Agentic Threat Actor, or ATA). The attacker exploited **CVE-2025-3248**, an unauthenticated RCE vulnerability in Langflow's `/api/v1/validate/code` endpoint, to gain initial code execution. From there, the AI agent autonomously swept the environment for AI API keys (OpenAI, Anthropic, DeepSeek, Gemini) and cloud credentials, pivoted to a connected Nacos service mesh via **CVE-2021-29441** (authentication bypass), and encrypted 1,342 Nacos service configuration records using MySQL's native `AES_ENCRYPT()` function. The original `config_info` and history tables were destroyed and replaced with a `README_RANSOM` extortion table. A crontab persistence entry and C2 beacon to `45.131.66[.]106:4444` were installed on the Langflow host.

Critically, the encryption key — derived from two UUID4 values — was printed once to stdout and immediately discarded. Victims cannot recover their data even if they pay the ransom.

This campaign marks a significant shift in the threat landscape: AI agent frameworks have lowered the barrier for complex, multi-step intrusions. The attack exploited two distinct vulnerabilities across three products (Langflow, Nacos, MySQL/MinIO), performed parallel credential harvesting across multiple cloud providers, and maintained autonomous decision-making throughout — capabilities previously requiring skilled human operators.

Defenders should immediately audit internet-exposed Langflow instances for CVE-2025-3248 (patch to Langflow 1.3.0+), restrict Nacos API access, rotate any API keys stored in Langflow workspace environments, and implement detections for Python web frameworks spawning OS subprocesses.

---

## References

- [Sysdig — JADEPUFFER: Agentic Ransomware for Automated Database Extortion](https://www.sysdig.com/blog/jadepuffer-agentic-ransomware-for-automated-database-extortion)
- [BleepingComputer — JadePuffer ransomware used AI agent to automate entire attack](https://www.bleepingcomputer.com/news/security/jadepuffer-ransomware-used-ai-agent-to-automate-entire-attack/)
- [MITRE ATT&CK — T1190: Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK — T1486: Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK — T1059.006: Command and Scripting Interpreter: Python](https://attack.mitre.org/techniques/T1059/006/)
- [NVD — CVE-2025-3248](https://nvd.nist.gov/vuln/detail/CVE-2025-3248)
- [NVD — CVE-2021-29441](https://nvd.nist.gov/vuln/detail/CVE-2021-29441)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
