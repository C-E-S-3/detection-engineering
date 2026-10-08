# PoeLLM — XMRig/Iron Cryptominer Execution and GitHub Poem C2 on AI Servers

## Description

Detects the PoeLLM cryptomining botnet (tracked as Canto Incognito by Lumen Black Lotus Labs) targeting internet-exposed AI and developer servers. PoeLLM deploys XMRig and Iron cryptocurrency miners, routes mining output to the Kryptex pool, and establishes C2 via a novel steganographic technique: an IPv4 address is encoded inside a GitHub-hosted poem, with the malware deriving the C2 IP by mapping specific words through a hard-coded dictionary.

This detection covers two phases: (1) miner execution — XMRig/Iron process spawning on systems running AI service software; (2) GitHub poem C2 resolution — AI service processes fetching raw GitHub content to resolve C2 addresses.

False positives for miner detection are rare; XMRig on production AI servers is almost always malicious. The GitHub raw-fetch detection may generate false positives from legitimate developer tooling; tune by baselining known-good GitHub fetches from each AI service's expected behavior. Exclude known CI/CD systems and package managers.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Command and Control |
| Tactic ID | TA0011 |
| Technique | Web Service: Dead Drop Resolver |
| Technique ID | T1102.001 |

Secondary mapping:

| Tactic | Technique | ID |
|--------|-----------|----|
| Initial Access | Exploit Public-Facing Application | T1190 |
| Impact | Resource Hijacking | T1496 |
| Discovery | Network Service Discovery | T1046 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Command & Control |
| Actions on Objectives |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name IN ("xmrig","xmrig64","xmrig-notls","xmrig.exe",
    "iron-miner","iron","xmrig-mo","xmrig-cuda")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=100
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_ip IN ("92.119.164.50","103.249.201.108","178.128.14.204",
    "191.37.28.160","89.39.253.46","120.224.114.212","5.78.73.122","15.204.178.28",
    "92.119.165.74","57.131.5.211")
     OR All_Traffic.dest_port=3778
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.process_name
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(dest,"92\.119\.164\.50|103\.249\.201\.108|178\.128\.14\.204"), 100,
    match(dest,"191\.37\.28\.160|89\.39\.253\.46|120\.224\.114\.212|5\.78\.73\.122|15\.204\.178\.28|92\.119\.165\.74|57\.131\.5\.211"), 85,
    dest_port=3778, 80,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime src dest dest_port process_name risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| XMRig/Iron miner process name match | 100 | Near-certain true positive on production AI server |
| Connection to active PoeLLM C2 IPs (92.119.164.50, 103.249.201.108, 178.128.14.204) | 100 | Known-malicious C2 active as of 2026-10-07 |
| Connection to historical PoeLLM C2 IPs | 85 | Infra may be reassigned; correlate with other indicators |
| Non-standard port 3778 (PoeLLM C2 beacon) | 80 | Unusual port; high signal in context of AI server |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| PoeLLM / Canto Incognito (unattributed; moderate confidence: Italian criminal) | [Lumen Black Lotus Labs Report](https://www.lumen.com/blog/en-us/canto-incognito-tracking-the-poellm-malware) |

## References

- [Canto incognito: tracking the PoeLLM malware — Lumen Black Lotus Labs](https://www.lumen.com/blog/en-us/canto-incognito-tracking-the-poellm-malware)
- [PoeLLM malware infects exposed AI servers in cryptomining attacks — BleepingComputer](https://www.bleepingcomputer.com/news/security/poellm-malware-infects-exposed-ai-servers-in-cryptomining-attacks/)
- [MITRE ATT&CK T1102.001 — Web Service: Dead Drop Resolver](https://attack.mitre.org/techniques/T1102/001/)
- [MITRE ATT&CK T1496 — Resource Hijacking](https://attack.mitre.org/techniques/T1496/)
- [CVE-2026-42271 — LiteLLM MCP RCE](https://nvd.nist.gov/vuln/detail/CVE-2026-42271)
