# Havoc C2 Framework Beaconing and Post-Exploitation Activity

## Description

Detects network and endpoint indicators of the Havoc open-source command-and-control framework, as used in the TrueChaos campaign (CVE-2026-3502 TrueConf exploitation, attributed to Amaranth Dragon — a suspected Chinese-nexus group targeting Southeast Asian government entities). Havoc communicates via HTTPS with a distinctive User-Agent, supports token impersonation, shellcode injection, and process injection. Its default listener uses port 443 with a self-signed certificate and a recognizable HTTP profile. Common false positives: legitimate HTTPS traffic on port 443; tune on the combination of User-Agent pattern, certificate fingerprint, and process injection indicators.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Command and Control |
| Tactic ID | TA0011 |
| Technique | Application Layer Protocol: Web Protocols |
| Technique ID | T1071.001 |

Secondary techniques: T1055 (Process Injection — shellcode injection), T1134 (Access Token Manipulation — token impersonation), T1573.002 (Encrypted Channel: Asymmetric Cryptography)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Command & Control (C2) |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_port IN (443, 8443, 40056)
    AND All_Traffic.app="ssl"
  by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port
     All_Traffic.ssl_subject All_Traffic.ssl_issuer All_Traffic.bytes_out
| `drop_dm_object_name(All_Traffic)`
| eval risk_score=case(
    match(ssl_issuer, "(?i)Havoc|havoc") OR match(ssl_subject, "(?i)Havoc"), 95,
    ssl_issuer==ssl_subject AND match(ssl_issuer, "^[A-Z]{2},"), 65,
    1=1, 40)
| where risk_score >= 65
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime src_ip dest_ip dest_port ssl_subject ssl_issuer bytes_out risk_score
```

**Supplemental: Havoc HTTP profile — distinctive User-Agent and beacon pattern**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Web.Web
  where Web.http_user_agent IN ("Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36")
  by Web.src Web.dest Web.http_user_agent Web.uri_path Web.bytes_in Web.bytes_out
| `drop_dm_object_name(Web)`
| eval beacon_score=case(
    match(http_user_agent, "Chrome/96\.0\.4664\.110"), 80,
    1=1, 50)
| where beacon_score >= 80
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime src dest http_user_agent uri_path bytes_in bytes_out beacon_score
```

**Supplemental: Havoc Demon agent — process injection and token manipulation**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name IN ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe")
    AND (Processes.process="*token*impersonat*" OR Processes.process="*inject*shellcode*"
         OR Processes.process="*VirtualAllocEx*" OR Processes.process="*WriteProcessMemory*")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| eval risk_score=case(
    match(process, "(?i)VirtualAllocEx|WriteProcessMemory|CreateRemoteThread"), 85,
    match(process, "(?i)token.*impersonat"), 80,
    1=1, 65)
| where risk_score >= 65
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

**Supplemental: TrueChaos campaign — UAC bypass via iscicpl.exe**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name="iscicpl.exe"
    AND NOT Processes.parent_process_name IN ("explorer.exe","mmc.exe","control.exe")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| eval risk_score=90
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| SSL cert with Havoc-specific issuer/subject | 95 | Default Havoc listener cert; near-certain TP in production environments |
| Self-signed cert matching Havoc default profile | 65 | Common in Havoc deployments; correlate with other indicators |
| Chrome/96 User-Agent (Havoc default HTTP profile) | 80 | Outdated browser version hardcoded in Havoc profiles; rare in legitimate traffic |
| Process injection API calls from interpreter process | 85 | Havoc Demon agent shellcode injection pattern |
| iscicpl.exe with non-standard parent | 90 | TrueChaos-specific UAC bypass TTP |

## Associated Threat Actors

| Actor | Relationship to Detection |
|-------|--------------------------|
| Amaranth Dragon | Chinese-nexus group; TrueChaos campaign exploiting TrueConf CVE-2026-3502 targeting SE Asian government entities; uses Havoc C2 hosted on Alibaba Cloud and Tencent |
| Various threat actors | Havoc is open-source and used broadly; also seen in Red Team operations and other intrusions |

## References

- [BleepingComputer - Hackers Exploit TrueConf Zero-Day to Push Malicious Updates (TrueChaos)](https://www.bleepingcomputer.com/news/security/hackers-exploit-trueconf-zero-day-to-push-malicious-software-updates/)
- [Havoc Framework (GitHub)](https://github.com/HavocFramework/Havoc)
- [MITRE ATT&CK - T1071.001 Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
- [MITRE ATT&CK - T1055 Process Injection](https://attack.mitre.org/techniques/T1055/)
