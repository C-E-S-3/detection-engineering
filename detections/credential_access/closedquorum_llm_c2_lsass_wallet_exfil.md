# CLOSEDQUORUM — LLM-Autonomous C2 Implant: LSASS Dump, Browser Credential Theft, and Crypto Wallet Exfiltration

## Description

Detects behavioral patterns associated with CLOSEDQUORUM, a 64-bit Windows Go implant disclosed by Cisco Talos on September 22, 2026. CLOSEDQUORUM is the first publicly documented malware to use a multi-LLM voting architecture (DeepSeek, Qwen, Mistral, Gemini) for fully autonomous C2 decision-making without a human operator.

The implant's `steal` action simultaneously performs LSASS memory credential dumping, Chrome/Edge/Firefox browser credential exfiltration, and MetaMask/Exodus/Ethereum crypto wallet extraction. The `inject` action uses AI-generated shellcode delivered via process hollowing or Early Bird APC injection.

These detections focus on durable behavioral indicators that fire regardless of binary hash or C2 infrastructure:
1. **Breadth-of-access pattern**: a single non-browser process accessing LSASS memory, browser credential stores, and crypto wallet directories within a short time window
2. **Unexpected LLM API egress**: outbound HTTPS from system processes to commercial AI provider endpoints
3. **Process injection anomalies**: legitimate Windows processes launched by unexpected parents

**False positive sources:**
- Security scanning tools with broad file-system access (CrowdStrike, Defender ATP) may touch credential paths — scope by process_name
- Developer environments with LLM tooling may generate outbound HTTPS to AI providers — exclude known dev processes and CIDR ranges
- EDR vendors performing LSASS reads for legitimate protection purposes

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic (Primary) | Credential Access |
| Tactic ID | TA0006 |
| Technique | OS Credential Dumping: LSASS Memory |
| Technique ID | T1003.001 |
| Secondary Tactic | Defense Evasion |
| Secondary Technique | Process Injection: Process Hollowing |
| Secondary Technique ID | T1055.012 |
| Secondary Technique | Process Injection: Asynchronous Procedure Call |
| Secondary Technique ID | T1055.004 |
| Additional Technique | Credentials from Password Stores: Credentials from Web Browsers |
| Additional Technique ID | T1555.003 |
| Additional Technique | Data from Local System |
| Additional Technique ID | T1005 |
| Additional Technique | Application Layer Protocol: Web Protocols (LLM API C2) |
| Additional Technique ID | T1071.001 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Actions on Objectives |
| Command & Control (LLM-based autonomous C2) |

## Splunk Detection Query

### Rule 1 — Breadth-of-Access: LSASS + Browser Credentials + Crypto Wallet (High Confidence)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path IN ("*\\lsass.dmp","*\\lsass*.dmp",
                                      "*\\Chrome\\User Data\\*\\Login Data",
                                      "*\\Microsoft\\Edge\\User Data\\*\\Login Data",
                                      "*\\Firefox\\Profiles\\*\\logins.json",
                                      "*\\MetaMask\\*","*\\Exodus\\*",
                                      "*\\Ethereum\\keystore\\*"))
    by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.process_id
       Filesystem.file_path Filesystem.file_name _time
| `drop_dm_object_name(Filesystem)`
| where NOT process_name IN ("chrome.exe","msedge.exe","firefox.exe",
                               "Exodus.exe","MetaMask.exe","MsMpEng.exe",
                               "SenseIR.exe","falcon-sensor.exe","csfalconservice.exe")
| eval file_class=case(
    match(file_path,"(?i)Login Data|logins.json"), "browser_creds",
    match(file_path,"(?i)MetaMask|Exodus|keystore"), "wallet",
    match(file_path,"(?i)lsass"), "lsass_dump",
    true(), "other"
)
| stats dc(file_class) as class_count count min(_time) as firstTime max(_time) as lastTime
    values(file_class) as file_classes values(file_path) as accessed_paths
    by dest user process_name process_id
| where class_count >= 2
| eval risk_score=case(class_count >= 3, 95, class_count = 2 AND match(file_classes,"lsass"), 90, class_count = 2, 75)
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user process_name process_id file_classes accessed_paths class_count risk_score
```

### Rule 2 — Unexpected Outbound HTTPS to LLM API Endpoints (AI C2 Indicator)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.dest_port=443
      AND (All_Traffic.dest IN ("api.deepseek.com","api.mistral.ai",
                                 "dashscope.aliyuncs.com","generativelanguage.googleapis.com"))
    by All_Traffic.src All_Traffic.dest All_Traffic.dest_port
       All_Traffic.src_ip All_Traffic.process_name All_Traffic.user
| `drop_dm_object_name(All_Traffic)`
| where NOT process_name IN ("chrome.exe","firefox.exe","msedge.exe","code.exe",
                               "python.exe","python3.exe","node.exe","cursor.exe",
                               "claude.exe","curl.exe","wget.exe","Postman.exe")
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    process_name IN ("svchost.exe","lsass.exe","csrss.exe","winlogon.exe","wininit.exe"), 95,
    isnull(process_name) OR process_name="", 85,
    true(), 70
)
| where risk_score >= 70
| table firstTime lastTime src dest process_name user risk_score count
```

### Rule 3 — Process Hollowing / Early Bird APC: Unexpected Parent for Hollowable Processes

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("svchost.exe","notepad.exe","calc.exe",
                                      "regsvr32.exe","rundll32.exe","msiexec.exe")
      AND NOT Processes.parent_process_name IN ("services.exe","wininit.exe","winlogon.exe",
                                                  "cmd.exe","powershell.exe","explorer.exe",
                                                  "msiexec.exe","taskhost.exe","taskhostw.exe",
                                                  "svchost.exe")
    by Processes.dest Processes.user Processes.parent_process_name
       Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    process_name="svchost.exe" AND NOT parent_process_name IN ("services.exe","wininit.exe"), 90,
    process_name IN ("regsvr32.exe","rundll32.exe") AND isnull(parent_process_name), 85,
    true(), 75
)
| where risk_score >= 75
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score count
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Single process accesses LSASS dump + wallet + browser creds | 95 | CLOSEDQUORUM `steal` module breadth-of-access signature |
| Single process accesses LSASS dump + one other credential class | 90 | High-confidence credential theft covering primary implant action |
| Single process accesses 2 non-LSASS credential classes | 75 | Strong indicator of infostealer; lower confidence without LSASS |
| Outbound HTTPS to LLM API from system process (svchost/lsass/csrss) | 95 | Near-certain AI C2 activity — these processes have no legitimate reason to call AI APIs |
| Outbound HTTPS to LLM API from unknown/null process | 85 | Process evasion; process hollowing may suppress name |
| Outbound HTTPS to LLM API from unexpected non-system process | 70 | Possible AI C2 from implant masquerading as non-dev process |
| Process hollowing: svchost launched by non-services.exe parent | 90 | Classic hollowing target with unexpected genealogy |
| Process hollowing: regsvr32/rundll32 with null parent | 85 | Injection artifact hiding parent lineage |

Composite (Rule 1 fires AND Rule 2 fires on same host within 10 minutes): **Critical (98)**.

## Associated Threat Actors

| Actor | Notes | References |
|-------|-------|-----------|
| CLOSEDQUORUM developer (unattributed) | Linked to carding forum posts (2025); no nation-state attribution; financially motivated cybercrime origin | [Cisco Talos — CLOSEDQUORUM (2026-09-22)](https://blog.talosintelligence.com/the-closed-quorum-inside-the-first-reported-autonomous-ai-c2-implant/) |

## References

- [Cisco Talos — The Closed Quorum: Inside the First Reported Autonomous AI C2 Implant (2026-09-22)](https://blog.talosintelligence.com/the-closed-quorum-inside-the-first-reported-autonomous-ai-c2-implant/)
- [CAIRN — Cisco Talos Open-Source AI Malware Detection Toolkit](https://github.com/Cisco-Talos/cairn)
- [MITRE ATT&CK — T1003.001: OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)
- [MITRE ATT&CK — T1055.012: Process Injection: Process Hollowing](https://attack.mitre.org/techniques/T1055/012/)
- [MITRE ATT&CK — T1055.004: Process Injection: Asynchronous Procedure Call](https://attack.mitre.org/techniques/T1055/004/)
- [MITRE ATT&CK — T1555.003: Credentials from Password Stores: Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003/)
- [MITRE ATT&CK — T1071.001: Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
