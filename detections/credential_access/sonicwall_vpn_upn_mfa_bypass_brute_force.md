# SonicWall SSL-VPN CLI Session Brute Force — CVE-2024-12802 MFA Bypass

## Description

Detects automated credential brute-forcing against SonicWall Gen6 SSL-VPN appliances exploiting CVE-2024-12802. The vulnerability allows authentication via the UPN (User Principal Name) login format without triggering MFA enforcement, even on appliances that received the official SonicOS patch — unless six additional manual post-patch hardening steps are completed. Attackers use automated tooling identifiable by the `sess="CLI"` session type in SonicWall authentication logs; legitimate interactive SSL-VPN web sessions never produce this session type value.

Campaign activity observed February–March 2026 shows a consistent 30–60 minute playbook: brute-force VPN credentials → successful authentication without MFA challenge → internal network sweep → credential reuse testing against internal systems → log off. Activity is attributed with low confidence to Akira ransomware affiliates based on TTP overlap with prior Akira SonicWall campaigns.

False positives: SonicWall CLI management sessions initiated by network administrators via SNMP or scripted API access may produce `sess="CLI"` entries; baseline expected CLI session sources and suppress known management IPs.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Credential Access |
| Tactic ID | TA0006 |
| Technique | Brute Force: Password Guessing |
| Technique ID | T1110.001 |

Secondary techniques: T1133 (External Remote Services — VPN as initial access vector), T1556 (Modify Authentication Process — MFA bypass via UPN format)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Actions on Objectives |

## Splunk Detection Query

```spl
`sonicwall` sess="CLI"
| bin _time span=5m
| stats count min(_time) as firstTime max(_time) as lastTime
    values(user) as users dc(user) as unique_users
  by src_ip dest
| where count >= 5
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(count>=30, 95, count>=20, 85, count>=10, 75, count>=5, 65)
| where risk_score >= 65
| table firstTime lastTime src_ip dest count unique_users users risk_score
```

**Supplemental: Successful VPN authentication via sess=CLI (MFA bypass success)**

```spl
`sonicwall` sess="CLI" (action=authenticated OR status=success)
| stats count min(_time) as firstTime max(_time) as lastTime by src_ip dest user
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime src_ip dest user count risk_score
```

**Supplemental: Authentication data model — high-frequency VPN auth failures (platform-agnostic)**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Authentication
  where Authentication.action="failure"
    AND (Authentication.app="SonicWall" OR Authentication.app="ssl-vpn")
  by Authentication.src Authentication.dest Authentication.app
| `drop_dm_object_name(Authentication)`
| bin firstTime span=10m
| stats sum(count) as attempt_count min(firstTime) as firstTime max(lastTime) as lastTime
  by src dest app
| where attempt_count >= 15
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(attempt_count>=50, 85, attempt_count>=25, 75, attempt_count>=15, 65)
| where risk_score >= 65
| table firstTime lastTime src dest app attempt_count risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| `sess="CLI"` auth success (MFA bypass achieved) | 90 | Critical: successful authentication via non-interactive session type bypassing MFA; requires immediate investigation |
| 30+ `sess="CLI"` attempts in 5 min from single source | 95 | Automated brute-force at high velocity; near-certain automated tooling |
| 20–29 `sess="CLI"` attempts in 5 min | 85 | High-confidence automated tooling |
| 10–19 `sess="CLI"` attempts in 5 min | 75 | Likely automated tooling; possible scripted management tool |
| 5–9 `sess="CLI"` attempts in 5 min | 65 | Suspicious; baseline management automation and suppress known admin sources |
| 15+ VPN auth failures in 10 min (platform-agnostic) | 65–85 | Brute force signal; correlate with successful auth following failure pattern |

## Associated Threat Actors

| Actor | Relationship to Detection |
|-------|--------------------------|
| Akira Ransomware Group | Assessed with low confidence as responsible for the February–March 2026 campaign exploiting CVE-2024-12802; Akira was previously linked to SonicWall credential abuse in 2025; post-access activity consistent with Akira pre-deployment playbook |

## References

- [BleepingComputer — Hackers bypass SonicWall VPN MFA due to incomplete patching (2026-05-20)](https://www.bleepingcomputer.com/news/security/hackers-bypass-sonicwall-vpn-mfa-due-to-incomplete-patching/)
- [Security Affairs — Attackers bypassing MFA on SonicWall VPNs because something was wrong with previous fix](https://securityaffairs.com/192477/hacking/attackers-are-bypassing-mfa-on-sonicwall-vpns-because-something-was-wrong-with-previous-fix.html)
- [MITRE ATT&CK — T1110.001 Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/)
- [MITRE ATT&CK — T1133 External Remote Services](https://attack.mitre.org/techniques/T1133/)
- [MITRE ATT&CK — T1556 Modify Authentication Process](https://attack.mitre.org/techniques/T1556/)
- [NVD — CVE-2024-12802](https://nvd.nist.gov/vuln/detail/CVE-2024-12802)
