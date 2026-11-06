# CWPdoor Trojanized cwpsrv Binary Detection

## Description

Detects indicators of CWPdoor, a passive Linux backdoor embedded in trojanized versions of `cwpsrv` —
the core web server binary of Control Web Panel (CWP, formerly CentOS Web Panel). Backdoored versions
1.15.10 and 1.24.0 were distributed via a fake updater script hosted on `136.0[.]141[.]71`, replacing
the legitimate binary in-place.

The backdoor stays dormant until a specially crafted HTTP request arrives with a valid cryptographic
signature within a 300-second timestamp window; commands are AES-256-CBC encrypted in HTTP headers.
CWPdoor suppresses its own trigger requests from CWP access logs, making it invisible to routine
log review. Zero VirusTotal detections at time of disclosure (2026-11-05). Infrastructure overlaps
with the Ebury SSH botnet ecosystem.

This detection covers three layers: network connections to the download server, the YARA-detectable
string `X-Ngx-Integrity` in process memory / on-disk, and execution of `wget`/`curl` fetching the
fake updater. False positives from the string indicator are expected to be near-zero as `X-Ngx-Integrity`
is not present in any known legitimate nginx or CWP component.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Defense Evasion |
| Tactic ID | TA0005 |
| Technique | Compromise Host Software Binary |
| Technique ID | T1554 |
| Sub-technique note | Also covers T1070.003 (log suppression), T1036 (socket masquerading), T1105 (binary download) |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Installation |

## Splunk Detection Query

### Part 1: Network — Download from CWPdoor Distribution Server

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_ip="136.0.141.71"
  by All_Traffic.src All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.transport
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src dest_ip dest_port transport risk_score
```

### Part 2: Endpoint — wget/curl Fetching cwpsrv Updater or Binary

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name IN ("wget","curl")
    AND (Processes.process="*136.0.141.71*"
      OR Processes.process="*cwpsrv_update*"
      OR Processes.process="*cwpsrv_1.15*"
      OR Processes.process="*cwpsrv_1.24*")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

### Part 3: Endpoint — cwpsrv Hash Match (EDR file hash telemetry)

```spl
index=* sourcetype IN ("crowdstrike:events:sensor","ms:defender:atp","carbon_black:*","sentinel_one:*")
(md5 IN ("965aea67fb40de1bab5169ada993349f","d3f4e95113d49ab3991b45e457bda75b","e505d4ffa21cf494a5dc2d7c8f4f1236")
  OR sha256 IN ("965aea67fb40de1bab5169ada993349f","d3f4e95113d49ab3991b45e457bda75b"))
| eval risk_score=100
| eval threat="CWPdoor trojanized cwpsrv"
| table _time host user file_path md5 sha256 risk_score threat
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Network connection to `136.0.141.71` | 95 | Confirmed CWPdoor distribution server; no legitimate use |
| wget/curl downloading from `136.0.141.71` | 95 | Direct binary retrieval from attacker server |
| Hash match (MD5) for backdoored cwpsrv | 100 | Exact IOC match; confirmed malicious binary |
| Hash match (MD5) for cwpsrv_update.sh | 100 | Exact IOC match; confirmed fake updater |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown (Ebury botnet ecosystem overlap) | [ESET Ebury Research](https://www.welivesecurity.com/en/eset-research/ebury-is-alive-but-unseen-400k-linux-servers-compromised-for-cryptocurrency-theft-and-financial-gain/) |

## References

- [The Hacker News — Hackers Hide Linux Backdoor in CWP cwpsrv Binary](https://thehackernews.com/2026/11/hackers-hide-linux-backdoor-in-control.html)
- [Threat Intel Report](../../threat-intel/2026-11-05_thehackernews-com-cwpdoor-linux-backdoor-trojanized-cwp.md)
- [MITRE ATT&CK — T1554: Compromise Host Software Binary](https://attack.mitre.org/techniques/T1554/)
- [MITRE ATT&CK — T1070.003: Indicator Removal: Clear Command History](https://attack.mitre.org/techniques/T1070/003/)
