---
scraped_at: 2026-11-04T00:00:00Z
source_url: https://blog.talosintelligence.com/volta-infostealer-llm-victim-ranking/
report_type: threat-intel
severity: medium
title: "VOLTA Infostealer: LLM-Assisted Victim Prioritization"
---

# VOLTA Infostealer: LLM-Assisted Victim Prioritization

**Source:** Cisco Talos  
**Published:** 2026-10-31  
**Severity:** Medium

---

## 1. IOCs

### File Hashes

| Hash | Type | Filename | Description |
|------|------|----------|-------------|
| `57ef4242666d78c50df145b34023df564f0fad38812d6a580e66433d427e2279` | SHA256 | `9BY0tjwOc3ut.exe` / `yLP9m5J3i2Aw.exe` | VOLTA infostealer main binary (randomized filename per victim) |

### File System Artifacts

| Path | Description |
|------|-------------|
| `%APPDATA%\volta_debug.txt` | VOLTA execution debug log written on startup |
| `%APPDATA%\volta_dox.zip` | Archive of harvested victim credentials and profile data |
| `%APPDATA%\volta_doxnet.zip` | Archive of harvested network/session data |

### Domains / Infrastructure

No confirmed C2 domains at time of publication. VOLTA sends harvested data to operator-controlled OpenRouter endpoints and uses legitimate AI provider APIs for scoring; no dedicated C2 domain was identified.

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique | Description |
|--------|-----------|-------------|
| TA0006 Credential Access | T1555 — Credentials from Password Stores | Harvests saved browser credentials, keychain data |
| TA0006 Credential Access | T1539 — Steal Web Session Cookie | Exfiltrates browser session cookies |
| TA0009 Collection | T1005 — Data from Local System | Collects local files, documents, and crypto wallet data |
| TA0040 Impact | T1657 — Financial Theft | LLM-assisted victim ranking prioritizes high-value targets for operator manual follow-up |
| TA0011 C2 | T1071.001 — Application Layer Protocol: Web | Exfiltrates over HTTPS to operator-controlled endpoints |
| TA0005 Defense Evasion | T1027 — Obfuscated Files or Information | Binary packed; randomized output filenames per victim |

**Novel TTP:** VOLTA submits a summary of harvested victim data (browser history, financial site visits, crypto wallet presence, geographic location) to an LLM API (Claude, Gemini, or Kimi via OpenRouter) and uses the structured response to rank the victim's financial value. High-scoring victims are flagged for immediate manual operator follow-up, while low-scoring victims receive automated credential-stuffing only. This is the first documented infostealer using LLM inference as a triage engine inside the malware itself.

---

## 3. Malware & Tools

### VOLTA

- **Type:** Windows infostealer
- **Language:** .NET (observed), possibly with a Rust-based packer stage
- **Distribution:** Phishing emails with password-protected archive attachments; malvertising lures
- **Key capability:** Post-collection LLM-based victim scoring using the OpenRouter API (supports Claude 3.5, Gemini 1.5 Flash, Kimi k1.5)
- **Output files:** `volta_dox.zip` (credentials), `volta_doxnet.zip` (network/session), `volta_debug.txt` (execution log)
- **Persistence:** No persistent mechanism observed; designed for single-session exfiltration

---

## 4. Threat Actor / Campaign Attribution

- **Threat Actor:** Unknown; Talos tracks as an independent campaign, no known group attribution
- **Motivation:** Financial — credential monetization and prioritized fraud follow-up
- **Targeting:** Broad consumer/SMB targeting; victim scoring selects for cryptocurrency holders, online banking users, and high-net-worth individuals
- **Geography:** English-speaking countries primary; global via malvertising

---

## 5. Splunk Detection Searches

### 5.1 VOLTA Debug File Creation in AppData

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_name IN ("volta_debug.txt", "volta_dox.zip", "volta_doxnet.zip")
    AND Filesystem.file_path="*\\AppData\\*"
  by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.process_id
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime dest user file_name file_path risk_score
```

### 5.2 LLM API Outbound Request from Non-Browser Process

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_port=443
    AND (All_Traffic.dest="openrouter.ai" OR All_Traffic.dest="api.anthropic.com"
         OR All_Traffic.dest="generativelanguage.googleapis.com")
  by All_Traffic.src All_Traffic.dest All_Traffic.app All_Traffic.process All_Traffic.user
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| where NOT (process="chrome.exe" OR process="firefox.exe" OR process="msedge.exe"
             OR process="brave.exe" OR process="safari" OR process="curl" OR process="python*")
| eval risk_score=65
| where risk_score >= 50
| table firstTime lastTime src dest app process user risk_score
```

### 5.3 Harvested Archive Creation in AppData (Generic Infostealer Pattern)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_name="*.zip"
    AND Filesystem.file_path="*\\AppData\\*"
    AND Filesystem.action=created
  by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.process_id
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(file_name, "(?i)(dox|cred|loot|steal|vault|wallet|dump)"), 80,
    1=1, 40)
| where risk_score >= 40
| table firstTime lastTime dest user file_name file_path risk_score
```

---

## 6. Executive Summary

VOLTA is a Windows infostealer first documented by Cisco Talos on 2026-10-31. Its primary novelty is the use of LLM APIs (Claude, Gemini, Kimi via OpenRouter) as an in-malware victim triage engine: after collecting credentials and browser data, VOLTA submits a victim profile to an LLM for financial value scoring before deciding whether to escalate the victim for manual operator follow-up. This reduces attacker workload by automatically filtering out low-value victims. The binary is distributed via phishing and malvertising with randomized filenames per victim. Known file artifacts (`volta_debug.txt`, `volta_dox.zip`, `volta_doxnet.zip`) provide high-confidence detection opportunities at the filesystem level. Priority action: deploy filesystem detection for VOLTA artifact filenames on endpoint security platforms.
