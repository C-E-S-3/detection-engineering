# Node2Shell CVE-2026-111497 Node.js Brotli Decoder RCE

## Description

Detects exploitation of CVE-2026-111497 (Node2Shell / HTTP2Shell / Broccoli2Shell), an out-of-bounds write vulnerability in the Brotli compression library (libbrotli) embedded in Node.js and other runtimes. A malformed `Content-Encoding: br` HTTP request body triggers heap corruption that can lead to remote code execution. CISA added this vulnerability to the Known Exploited Vulnerabilities catalog on October 28, 2026. Active exploitation traffic was observed by ELLIO from IP `94.154.43[.]7` on October 26, 2026 — the same host previously linked to PHP2Shell (CVE-2026-109618/109619) scanning.

The vulnerability affects Node.js 22.x before 22.23.4, 24.x before 24.22.1, and 26.x before 26.12.1, as well as standalone Brotli library builds 1.0.x before 1.0.10, 1.1.x before 1.1.1, and 1.2.x before 1.2.1. .NET was also patched on October 25, 2026.

**False positives:** Large `Content-Encoding: br` POST requests can be legitimate for APIs accepting Brotli-compressed payloads. Node.js spawning shells may fire on legitimate build tools (`npm run build`, `child_process.exec` in application code). Tune the process-spawn query against known-good baselines for your environment.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |
| Secondary Techniques | T1059 (Command and Scripting Interpreter — post-exploitation shell) |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Delivery |
| Exploitation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN ("node", "nodejs", "python3", "python", "ruby", "go")
  AND Processes.process_name IN ("sh", "bash", "dash", "zsh", "cmd.exe", "powershell.exe",
                                  "curl", "wget", "nc", "ncat", "python3", "python")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    process_name IN ("cmd.exe","powershell.exe"), 85,
    process_name IN ("nc","ncat"), 88,
    process_name IN ("sh","bash","dash","zsh") AND NOT match(process, "npm|yarn|node_modules"), 82,
    1=1, 60)
| where risk_score >= 82
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

### Supplemental: Known Exploitation Source IP

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where (All_Traffic.src_ip="94.154.43.7" OR All_Traffic.dest_ip="94.154.43.7")
  by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.action
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85
| table firstTime lastTime src_ip dest_ip dest_port action risk_score
```

### Supplemental: Node.js Worker Crash Loop (SIGSEGV / Brotli Decode Failure)

```spl
index=* sourcetype IN ("syslog","linux_secure","journald","docker_logs")
  (process="node" OR process="nodejs")
  ("SIGSEGV" OR "exit code 139" OR "ERR__ERROR_FORMAT_BLOCK_SWITCH" OR "brotli: decoder failed" OR "brotli: decoder is unhealthy")
| bucket _time span=5m
| stats count as crash_count by _time host process
| where crash_count >= 3
| eval risk_score=case(crash_count >= 5, 75, crash_count >= 3, 65, 1=1, 45)
| where risk_score >= 65
| table _time host process crash_count risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| `nc` or `ncat` spawned by Node.js | 88 | Reverse shell tool; no legitimate Node.js parent |
| `cmd.exe`/`powershell.exe` spawned by Node.js | 85 | Windows post-exploitation shell from server runtime |
| Connection to/from `94.154.43.7` | 85 | CISA KEV-associated exploitation IP; linked to multiple active exploit campaigns |
| `sh`/`bash` spawned by Node.js (non-npm) | 82 | Post-exploitation shell; filter npm/yarn/node_modules for FP reduction |
| 5+ Node.js SIGSEGV / Brotli decoder crashes in 5 min | 75 | Crash loop consistent with exploitation attempts (may also be probing) |
| 3+ crashes in 5 min | 65 | Lower-confidence crash indicator |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown / Opportunistic | ELLIO telemetry — IP 94.154.43.7 linked to PHP2Shell and VPN-probing campaigns Oct 2026; no group attribution published |

## References

- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- Help Net Security: https://www.helpnetsecurity.com/2026/10/27/node2shell-broccoli2shell-vulnerability-cve-2026-111497/
- Rescana: https://www.rescana.com/post/nodejs-cve-2026-111497-node2shell-brotli-rce-october-2026
- Zscaler ThreatLabZ: https://www.zscaler.com/blogs/security-research/cve-2026-111497-node2shell-http2shell-vulnerability-may-allow-rce
- Sysdig: https://www.sysdig.com/blog/node2shell-cve-2026-111497-detecting-the-node-js-brotli-rce
- GitHub detection gist: https://gist.github.com/Blevene/7d9d769f54826e1fe770d8c19d5ef0b2
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-111497
- GHSA: https://github.com/advisories/GHSA-9v8h-qqgm-4m35
- MITRE T1190: https://attack.mitre.org/techniques/T1190/
