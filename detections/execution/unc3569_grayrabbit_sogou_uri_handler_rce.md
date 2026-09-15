# UNC3569 GRAYRABBIT — Sogou IME URI Handler Exploitation (CVE-2026-51990)

## Description

Detects exploitation of CVE-2026-51990 in Tencent's Sogou Input Method for Windows. The vulnerability is triggered by a crafted `sgbiz:` URI that chains three weaknesses: unvalidated command-line argument injection in the URI handler, unrestricted URL navigation in Sogou's CEF (Chromium Embedded Framework) webview, and remote code execution via an outdated, unsandboxed Chromium 80 engine. Successful exploitation deploys the GRAYRABBIT backdoor, which communicates with `mail.uaiubifas[.]top:443` using RC4-encrypted TCP. Used by UNC3569, a China-linked hacker-for-hire group targeting government, education, technology, and financial sectors in East and Southeast Asia.

The primary detection angle is `biz_helper.exe` — the Sogou URI handler process — spawning unexpected child processes, and network connections to the known C2 domain. False positive sources are minimal: `biz_helper.exe` has no legitimate reason to spawn command interpreters or write executables. A secondary detection targets Sogou CEF subprocess outbound connections to non-Sogou infrastructure.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Execution |
| Tactic ID | TA0002 |
| Technique | Exploitation for Client Execution |
| Technique ID | T1203 |

Secondary techniques: T1566.002 (Phishing: Spearphishing Link — initial delivery), T1071.001 (C2 via HTTPS/TCP), T1059.003 (Windows Command Shell via reverse shell)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Installation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN ("biz_helper.exe","SogouExe.exe")
    AND Processes.process_name IN (
      "cmd.exe","powershell.exe","curl.exe","certutil.exe",
      "wscript.exe","mshta.exe","regsvr32.exe","rundll32.exe",
      "bitsadmin.exe","msiexec.exe"
    )
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    process_name IN ("cmd.exe","powershell.exe"), 95,
    process_name IN ("curl.exe","certutil.exe","bitsadmin.exe"), 95,
    process_name IN ("wscript.exe","mshta.exe","regsvr32.exe","rundll32.exe","msiexec.exe"), 90,
    1=1, 80)
| where risk_score >= 80
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_host="mail.uaiubifas.top"
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_host All_Traffic.dest_port All_Traffic.bytes_in All_Traffic.bytes_out
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=100
| table firstTime lastTime src dest dest_host dest_port bytes_in bytes_out risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Resolution.DNS
  where DNS.query="mail.uaiubifas.top"
  by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=100
| table firstTime lastTime src query answer risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| biz_helper.exe spawns cmd.exe or PowerShell | 95 | Shell launch from Sogou URI handler has no legitimate use case; near-certain exploitation |
| biz_helper.exe spawns curl.exe, certutil.exe, or bitsadmin.exe | 95 | Download utility from URI handler = post-exploit payload retrieval |
| Network connection or DNS query to mail.uaiubifas[.]top | 100 | Known GRAYRABBIT C2 domain; confirmed IOC with no legitimate use |
| biz_helper.exe spawns any other non-Sogou process | 80 | Anomalous child process; requires triage |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| UNC3569 (China-linked hacker-for-hire) | [Gen Digital: Gray Rabbits and the Tale of a One-Click Backdoor](https://www.gendigital.com/blog/insights/research/one-click-backdoor-sogou), [VB2024: Down the GRAYRABBIT Hole](https://www.virusbulletin.com/uploads/pdf/conference/vb2024/papers/Down-the-GRAYRABBIT-hole-exposing-UNC3569-and-its-modus-operandi.pdf) |

## References

- [BleepingComputer: Hackers exploit Tencent app flaw to deploy GrayRabbit malware](https://www.bleepingcomputer.com/news/security/hackers-exploit-tencent-app-flaw-to-deploy-grayrabbit-malware/)
- [Gen Digital: Gray Rabbits and the Tale of a One-Click Backdoor](https://www.gendigital.com/blog/insights/research/one-click-backdoor-sogou)
- [The Hacker News: China-Linked UNC3569 Exploited Sogou Input Method Flaw to Deploy GRAYRABBIT Backdoor](https://thehackernews.com/2026/09/china-linked-unc3569-exploited-sogou.html)
- [NVD: CVE-2026-51990](https://nvd.nist.gov/vuln/detail/CVE-2026-51990)
- [MITRE ATT&CK: T1203 Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203/)
