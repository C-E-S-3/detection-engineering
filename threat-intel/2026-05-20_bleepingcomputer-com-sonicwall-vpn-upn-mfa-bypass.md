---
scraped_at: "2026-05-22T00:00:00Z"
source_url: "https://www.bleepingcomputer.com/news/security/hackers-bypass-sonicwall-vpn-mfa-due-to-incomplete-patching/"
report_type: threat-intel
severity: high
title: "SonicWall Gen6 SSL-VPN MFA Bypass via Incomplete CVE-2024-12802 Patch — Akira Ransomware Campaigns"
---

## 1. IOCs

No network IOCs (IP/domain/hash) attributed to this specific campaign. The key indicator is behavioral: rapid VPN authentication attempts using the `sess="CLI"` session type from a single source IP, consistent with automated brute-force tooling.

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Credential Access | T1110.001 | Brute Force: Password Guessing | Attackers use automated tools (sess="CLI" session type) to brute-force VPN credentials against SonicWall Gen6 SSL-VPN; attempts arrive in rapid succession from a single source IP |
| Initial Access | T1133 | External Remote Services | SonicWall Gen6 SSL-VPN serves as the initial access vector; CVE-2024-12802 allows authentication via UPN login format that bypasses MFA enforcement even on patched appliances without manual post-patch configuration steps |
| Defense Evasion | T1556 | Modify Authentication Process | CVE-2024-12802: Missing MFA enforcement for UPN (User Principal Name) login format; the patch addresses the vulnerability but requires six additional manual configuration steps that are often missed, leaving MFA bypassable |
| Discovery | T1018 | Remote System Discovery | Post-access internal network sweep; observed within 30–60 minutes of successful VPN authentication |
| Lateral Movement | T1021.001 | Remote Services: Remote Desktop Protocol | Credential reuse against internal systems following network sweep |

## 3. Malware & Tools

No specific malware families identified in the initial access phase. Post-compromise activity is consistent with Akira ransomware affiliate pre-deployment tooling (network sweeping, credential testing). Automated brute-force tooling is unspecified but identified via the `sess="CLI"` session type fingerprint in SonicWall logs.

## 4. Threat Actor / Campaign Attribution

**Attribution:** Unconfirmed; activity pattern is consistent with Akira ransomware affiliate TTPs observed in 2025–2026 SonicWall targeting campaigns. Akira was previously linked to SonicWall credential abuse in 2025.

**Campaign window observed:** February – March 2026 (intrusion analysis); public disclosure May 20, 2026.

**Affected models:** NSa 2700, NSa 3700, NSa 4700, NSa 5700, NSa 6700 running SonicOS 7.0 through 7.1.1.

**Root cause:** CVE-2024-12802 (authentication bypass via UPN login format) was patched in SonicOS firmware but requires six additional manual post-patch steps. Organizations that applied only the firmware update without completing the manual hardening steps remain exploitable.

**Key detection signal:** All observed brute-force sessions used `sess="CLI"` as the session type, a non-standard value indicating automated tooling rather than interactive user login. Legitimate SonicWall SSL-VPN web sessions use a different session type identifier.

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Authentication
  where Authentication.app="SonicWall" AND Authentication.action="failure"
  by Authentication.src Authentication.dest Authentication.user Authentication.app
| `drop_dm_object_name(Authentication)`
| bin firstTime span=5m
| stats sum(count) as attempt_count min(firstTime) as firstTime max(lastTime) as lastTime
    values(user) as users dc(user) as unique_users
  by src dest app
| where attempt_count >= 10
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(attempt_count>=30, 90, attempt_count>=20, 80, attempt_count>=10, 70)
| where risk_score >= 70
| table firstTime lastTime src dest app attempt_count unique_users users risk_score
```

```spl
`sonicwall` sess="CLI"
| stats count min(_time) as firstTime max(_time) as lastTime values(user) as users dc(user) as unique_users
  by src_ip dest
| where count >= 5
| eval risk_score=case(count>=20, 90, count>=10, 80, count>=5, 70)
| where risk_score >= 70
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime src_ip dest count unique_users users risk_score
```

```spl
`sonicwall` sess="CLI" action=authenticated
| stats count min(_time) as firstTime max(_time) as lastTime by src_ip dest user
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85
| table firstTime lastTime src_ip dest user count risk_score
```

## 6. Executive Summary

Threat actors exploiting CVE-2024-12802 in SonicWall Gen6 SSL-VPN appliances (NSa series, SonicOS 7.0–7.1.1) bypassed MFA enforcement through an incomplete patch. The vulnerability allows authentication via the UPN login format without triggering MFA, and remains exploitable on patched appliances if six additional manual post-patch hardening steps are not completed.

Researchers observed a campaign between February and March 2026 in which attackers used automated tools to brute-force VPN credentials — identifiable by the `sess="CLI"` session type in SonicWall authentication logs — and successfully authenticated without triggering MFA challenges. Following successful VPN access, attackers followed a consistent 30–60 minute playbook: sweep the internal network, test credential reuse against internal systems, then log out. Activity is assessed as consistent with Akira ransomware affiliate pre-deployment reconnaissance.

The key detection opportunity is the `sess="CLI"` session type in VPN authentication logs: no legitimate interactive user session uses this type. Organizations should monitor for this value combined with high-frequency authentication attempts from a single source, and immediately audit whether all post-patch manual hardening steps have been applied to all affected appliances.
