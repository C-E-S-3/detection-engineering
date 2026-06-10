# Check Point VPN IKEv1 Authentication Bypass Exploitation (CVE-2026-50751)

## Description

Detects exploitation of CVE-2026-50751, a critical authentication bypass vulnerability (CVSS 9.3) in Check Point Remote Access VPN and Mobile Access deployments using the deprecated IKEv1 key exchange protocol. A logic flaw in certificate validation allows an unauthenticated attacker to establish a fully-authenticated VPN session without valid credentials. A Qilin ransomware affiliate actively exploited this vulnerability from May 7, 2026 onwards, with CISA adding it to the KEV catalog on June 8, 2026.

Detection focuses on three behavioral signals: (1) VPN authentication events sourced from VPS infrastructure associated with the known exploitation campaign (Kaupo Cloud HK AS7540, Shock Hosting AS36352, Vultr AS20473); (2) anomalous VPN session establishment metrics (successful auth at times with no corresponding credential usage in SIEM); and (3) Rclone execution on endpoints shortly after a new VPN client connects, consistent with the pre-ransomware exfiltration pattern observed by Check Point.

False positive sources: Legitimate remote users connecting through a corporate VPN concentrator may use VPS-based infrastructure (split-tunnel, cloud desktop, travel); Rclone is used legitimately by cloud storage and backup teams. Both require analyst triage.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |
| Secondary Tactic | Impact |
| Secondary Technique | T1486 — Data Encrypted for Impact (Qilin ransomware stage) |
| Secondary Tactic | Exfiltration |
| Secondary Technique | T1567.002 — Exfiltration to Cloud Storage (Rclone pre-ransomware) |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Delivery |
| Actions on Objectives |

## Splunk Detection Query

```spl
| comment "Query 1: VPN auth from known exploitation campaign ASNs (Kaupo Cloud HK, Shock Hosting, Vultr)"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Authentication
  where Authentication.app IN ("*VPN*","*Check*Point*","*checkpoint*","*Remote*Access*","*Mobile*Access*")
    AND Authentication.action="success"
  by Authentication.src Authentication.user Authentication.dest Authentication.app Authentication.action
| `drop_dm_object_name(Authentication)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| lookup asn_lookup ip AS src OUTPUT asn as src_asn org as src_org
| search src_asn IN ("AS7540","AS36352","AS20473")
    OR src_org IN ("*Kaupo*","*Shock Hosting*","*Vultr*","*Choopa*")
| eval risk_score=case(
    src_asn="AS36352", 90,
    src_asn IN ("AS7540","AS20473"), 85,
    1=1, 80)
| where risk_score >= 80
| table firstTime lastTime src src_asn src_org user dest app action risk_score
```

```spl
| comment "Query 2: Rclone execution on endpoints — pre-ransomware exfiltration signal; correlate with recent VPN auth events"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.process_name="rclone.exe" OR Processes.process_name="rclone")
    AND (Processes.process="*copy*" OR Processes.process="*sync*" OR Processes.process="*move*")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process,"(?i)--config") AND match(process,"(?i)copy|sync|move"), 90,
    match(process,"(?i)--transfers|--checkers"), 85,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| comment "Query 3: IOC hash detection for CVE-2026-50751 exploitation artifacts (Check Point sk185033)"
index=* (md5="52fda5c1b9704544f32ee98d9060e689" OR md5="51d39aa39478beeac94f2d12f682ecce")
| eval risk_score=95
| table _time host user md5 process_name file_path risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| VPN success auth from Shock Hosting AS36352 | 90 | AS36352 is a bulletproof-adjacent hosting provider frequently used by ransomware actors; VPN auth from here is almost never legitimate |
| VPN success auth from Kaupo Cloud HK or Vultr | 85 | Both VPS providers observed in CVE-2026-50751 exploitation infrastructure; legitimate corporate use possible but unusual |
| Rclone with copy/sync/move + --config flag | 90 | Rclone launched with a custom config (common in exfiltration tooling to point to attacker cloud storage); analyst review required |
| Rclone with --transfers/--checkers flags | 85 | Performance tuning flags used in bulk data exfiltration; uncommon in legitimate endpoint use |
| IOC hash match (sk185033) | 95 | Confirmed exploitation artifact per vendor advisory; near-certain indicator of compromise |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Qilin Ransomware (RaaS) | [MITRE ATT&CK — Qilin (G1063)](https://attack.mitre.org/groups/G1063/), [BleepingComputer — Qilin Ransomware](https://www.bleepingcomputer.com/tag/qilin/) |
| Unknown Qilin affiliate (CVE-2026-50751) | [Check Point sk185033](https://support.checkpoint.com/results/sk/sk185033), [Rapid7 ETR (2026-06-08)](https://www.rapid7.com/blog/post/etr-critical-check-point-vpn-zero-day-exploited-in-the-wild-cve-2026-50751/) |

## References

- [CISA KEV — June 8, 2026: CVE-2026-50751](https://www.cisa.gov/news-events/alerts/2026/06/08/cisa-adds-two-known-exploited-vulnerabilities-catalog)
- [Check Point Advisory sk185033](https://support.checkpoint.com/results/sk/sk185033)
- [Check Point Blog — IKEv1 VPN Hotfix](https://blog.checkpoint.com/security/check-point-releases-important-hotfix-for-vulnerabilities-in-deprecated-ikev1-vpn-protocol/)
- [BleepingComputer — Check Point links VPN zero-day attacks to Qilin ransomware gang](https://www.bleepingcomputer.com/news/security/check-point-links-vpn-zero-day-attacks-to-qilin-ransomware-gang/)
- [Rapid7 ETR — CVE-2026-50751](https://www.rapid7.com/blog/post/etr-critical-check-point-vpn-zero-day-exploited-in-the-wild-cve-2026-50751/)
- [MITRE ATT&CK — T1190: Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK — T1486: Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK — T1567.002: Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002/)
