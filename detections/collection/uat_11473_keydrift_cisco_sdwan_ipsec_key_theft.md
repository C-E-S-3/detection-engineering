# UAT-11473 KeyDrift: Cisco SD-WAN IPsec Key Material Theft

## Description

Detects activity associated with the KeyDrift malware framework deployed by UAT-11473 against Cisco Catalyst SD-WAN Controllers, Managers, and Validators. KeyDrift consists of two components: **LittleFilch** (`libcommon.so`), which hooks `SSL_read` in the `vdaemon` process to extract 32-byte AES-256 IPsec key material from decrypted control-plane messages; and **PolyFlame** (`libdssl.so`), an in-memory backdoor receiving operator commands embedded inside legitimate SD-WAN control traffic.

Entry is via **CVE-2026-20127** (CVSS 10.0), an authentication bypass in the Cisco SD-WAN Manager REST API patched in February 2026.

UAT-11473 infrastructure overlaps with high confidence with Volt Typhoon's "Silent Train" ORB relay network. Targets include space and satellite services, defense aerospace, and policy research organizations. IPsec key exfiltration enables passive decryption of captured enterprise WAN traffic.

**Expected false positives:** Low for rogue library and runit modification detections — these are near-zero-noise on appliances with stable configurations. API anomaly detections may fire on aggressive vulnerability scanners or misconfigured SD-WAN integrations that retry authentication.

## MITRE ATT&CK Mapping

- **Primary Tactic:** Collection (TA0009)
- **Primary Technique:** T1119 — Automated Collection
- **Secondary Tactics/Techniques:**
  - Initial Access (TA0001) / T1190 — Exploit Public-Facing Application (CVE-2026-20127)
  - Persistence (TA0003) / T1543.001 — Create or Modify System Process: Init Script Modification (runit)
  - Defense Evasion (TA0005) / T1036.005 — Masquerading: Match Legitimate Name or Location (libcommon.so, libdssl.so)
  - Defense Evasion (TA0005) / T1055 — Process Injection (SSL_read hook in vdaemon)
  - Command and Control (TA0011) / T1205 — Traffic Signaling (commands embedded in SD-WAN control traffic)

## Lockheed Martin Kill Chain Phase

- **Primary:** Actions on Objectives (IPsec key extraction and staging)
- **Secondary:** Delivery / Exploitation (CVE-2026-20127 exploitation); Installation (runit persistence)

## Splunk Detection Query

### Detection 1 — CVE-2026-20127 Authentication Bypass Exploitation Attempt (Initial Access)

```spl
`cisco_sdwan` sourcetype=cisco:sdwan:audit
| search uri_path IN ("/dataservice/client/token", "/dataservice/j_security_check",
                      "/dataservice/v1/token", "/dataservice/admin/*",
                      "/dataservice/settings/clientId")
| bin _time span=5m
| stats count
        values(status) as statuses
        values(src_ip) as src_ips
        min(_time) as firstTime max(_time) as lastTime
  by host uri_path
| where count > 3 AND (mvfind(statuses, "200") >= 0 OR mvfind(statuses, "401") >= 0)
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    mvfind(statuses,"200") >= 0 AND mvfind(statuses,"401") >= 0, 90,
    mvfind(statuses,"200") >= 0, 75,
    true(), 50
  )
| where risk_score >= 50
| table firstTime lastTime host uri_path src_ips statuses count risk_score
```

### Detection 2 — KeyDrift Implant Artifact Presence in SD-WAN Controller Logs

```spl
`cisco_sdwan` sourcetype IN (cisco:sdwan:syslog, cisco:sdwan:audit)
| search (message IN ("*libcommon.so*", "*libdssl.so*")
          OR process_path IN ("*libcommon.so*", "*libdssl.so*")
          OR message="*vdaemon*" AND (message="*libcommon*" OR message="*libdssl*"))
| stats count
        values(message) as log_messages
        values(process_path) as process_paths
        min(_time) as firstTime max(_time) as lastTime
  by host src_user
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime host src_user log_messages process_paths count risk_score
```

### Detection 3 — Cisco SD-WAN Controller Unexpected runit Init Script Modification

```spl
`cisco_sdwan` sourcetype=cisco:sdwan:syslog
| search message IN ("*runit*", "*sv *", "*/etc/service/*", "*/etc/sv/*")
          AND (message IN ("*modified*", "*updated*", "*created*", "*write*", "*chmod*"))
| stats count
        values(message) as log_messages
        min(_time) as firstTime max(_time) as lastTime
  by host src_user
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=80
| table firstTime lastTime host src_user log_messages count risk_score
```

## Risk Score Logic

| Score | Condition |
|-------|-----------|
| 95 | Artifact filenames `libcommon.so` or `libdssl.so` appear in SD-WAN controller logs — near-certain indicator of KeyDrift installation |
| 90 | Auth-bypass endpoint hit with mixed 401/200 status codes in same 5-minute window — strongly suggests active CVE-2026-20127 exploitation |
| 80 | runit init script modification detected on SD-WAN controller — likely KeyDrift persistence activity |
| 75 | Auth-bypass API endpoint returns HTTP 200 with no prior session — anomalous successful access |
| 50 | High-volume auth-bypass endpoint access — possible scanning / exploitation attempt |

## Associated Threat Actors

| Actor | Designation | Notes |
|-------|-------------|-------|
| UAT-11473 | Cisco Talos threat cluster | Directly attributed to KeyDrift campaign; disclosed October 28, 2026 |
| Volt Typhoon (Voltzite / Bronze Silhouette) | China-nexus nation-state APT | High-confidence infrastructure overlap via "Silent Train" ORB; Talos does not assert operational identity with UAT-11473 |

## References

- [Cisco Talos — UAT-11473 KeyDrift](https://blog.talosintelligence.com/uat-11473-keydrift/) (October 28, 2026)
- [Cisco Security Advisory — CVE-2026-20127 (cisco-sa-sdwan-rpa-EHchtZk)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-rpa-EHchtZk)
- [MITRE ATT&CK — T1119 Automated Collection](https://attack.mitre.org/techniques/T1119/)
- [MITRE ATT&CK — T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK — T1543.001 Create or Modify System Process: Init Daemon](https://attack.mitre.org/techniques/T1543/001/)
- [MITRE ATT&CK — T1205 Traffic Signaling](https://attack.mitre.org/techniques/T1205/)
- [Lumen Black Lotus Labs — Volt Typhoon Silent Train ORB](https://blog.lumen.com/volt-typhoon-silent-train-orb/)
- [CISA — Volt Typhoon Advisory (AA24-038A)](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a)
