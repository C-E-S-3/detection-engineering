---
scraped_at: 2026-11-04T00:00:00Z
source_url: https://www.bleepingcomputer.com/news/security/cerber-ransomware-returns-as-c3rb3r-targeting-synology-nas/
report_type: threat-intel
severity: high
title: "C3RB3R Ransomware Targeting Synology NAS Devices"
---

# C3RB3R Ransomware Targeting Synology NAS Devices

**Source:** BleepingComputer / Synology PSIRT  
**Published:** 2026-11-02  
**Severity:** High

---

## 1. IOCs

### File Hashes

| Hash | Type | Description |
|------|------|-------------|
| `a1375e0f82ae86df528876c049b5a23c` | MD5 | C3RB3R ransomware encryptor binary (single unconfirmed source; treat as low-confidence pending corroboration) |

### File System Artifacts

| Indicator | Description |
|-----------|-------------|
| `*.L0CK3D` file extension | Files encrypted by C3RB3R receive this extension (e.g., `document.pdf.L0CK3D`) |
| `read-me3.txt` | C3RB3R ransom note filename, dropped in each encrypted directory |

### CVEs

| CVE | Product | CVSS | Description |
|-----|---------|------|-------------|
| CVE-2024-10441 | Synology DiskStation Manager | Critical | Unauthenticated RCE via DSM web interface; patched in DSM 7.4-90075, 7.3.2-86009-4, 7.2.2-72806-9, 7.2.1-69057-12 |
| CVE-2026-13639 | Synology DSM (attributed by Qihoo 360) | High | Secondary DSM vulnerability used in C3RB3R attack chain (unconfirmed) |
| CVE-2026-13684 | Synology DSM (attributed by Qihoo 360) | High | Secondary DSM vulnerability used in C3RB3R attack chain (unconfirmed) |

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique | Description |
|--------|-----------|-------------|
| TA0001 Initial Access | T1190 — Exploit Public-Facing Application | Exploits CVE-2024-10441 (and possibly others) for unauthenticated RCE on Synology DSM |
| TA0040 Impact | T1486 — Data Encrypted for Impact | Encrypts NAS files with `.L0CK3D` extension and drops `read-me3.txt` ransom note |
| TA0040 Impact | T1489 — Service Stop | Stops DSM services prior to encryption to unlock files |
| TA0005 Defense Evasion | T1562.001 — Impair Defenses: Disable or Modify Tools | Disables Synology-bundled antivirus and backup services before encrypting |

---

## 3. Malware & Tools

### C3RB3R (Cerber-family)

- **Type:** Ransomware targeting Synology NAS / Linux ARM/x86-64
- **Family:** Cerber-family (modernized fork, hence "C3RB3R" branding)
- **Encryption marker:** `.L0CK3D` extension
- **Ransom note:** `read-me3.txt`
- **Entry vector:** Unauthenticated RCE via Synology DSM web interface (CVE-2024-10441)
- **Patched versions:** DSM 7.4-90075 / 7.3.2-86009-4 / 7.2.2-72806-9 / 7.2.1-69057-12

---

## 4. Threat Actor / Campaign Attribution

- **Threat Actor:** Unknown; Synology PSIRT and BleepingComputer attribute to an unidentified ransomware operator leveraging the Cerber codebase
- **Motivation:** Financial — ransomware extortion
- **Targeting:** Synology NAS devices exposed to the internet with unpatched DSM firmware
- **Volume:** Multiple victims reported across Europe and Asia-Pacific; exact scale unknown

---

## 5. Splunk Detection Searches

### 5.1 C3RB3R Encrypted File Extension on Network Shares

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_name="*.L0CK3D"
  by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime dest user file_name file_path risk_score
```

### 5.2 Ransomware Note File Creation (`read-me3.txt`)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_name="read-me3.txt"
  by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.action
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime dest user file_name file_path action risk_score
```

### 5.3 High-Rate File Rename/Modification on NAS (Ransomware Encryption Behavior)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.action="modified" OR Filesystem.action="renamed"
  by Filesystem.dest Filesystem.user _time span=1m
| `drop_dm_object_name(Filesystem)`
| where count > 500
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=75
| table firstTime lastTime dest user count risk_score
```

### 5.4 Synology DSM Exploitation Attempt (CVE-2024-10441)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Web.Web
  where Web.dest_port IN (5000, 5001)
    AND (Web.uri_path="*/entry.cgi*" OR Web.uri_path="*/auth.cgi*")
    AND Web.status IN (200, 302)
  by Web.src Web.dest Web.uri_path Web.user_agent Web.status
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=60
| where risk_score >= 50
| table firstTime lastTime src dest uri_path user_agent status risk_score
```

---

## 6. Executive Summary

C3RB3R, a modernized variant of the Cerber ransomware family, is actively targeting Synology NAS devices exposed to the internet by exploiting CVE-2024-10441, a critical unauthenticated RCE flaw in Synology DiskStation Manager. After gaining access, the ransomware encrypts files with the `.L0CK3D` extension and drops a `read-me3.txt` ransom note in each directory. Synology has released patches across all supported DSM branches. Organizations running Synology NAS should immediately apply DSM updates (7.4-90075, 7.3.2-86009-4, 7.2.2-72806-9, or 7.2.1-69057-12) and restrict internet access to the DSM web interface until patched. Detection relies on filesystem monitoring for the `.L0CK3D` extension and ransom note filename, as well as anomalously high file rename rates indicative of active encryption.
