# Fox Tempest — Malware Signed via Azure Artifact Signing Abuse

## Description

Detects execution of malware signed using Fox Tempest's malware-signing-as-a-service (MSaaS), which abused Microsoft Azure Artifact Signing to generate fraudulent 72-hour Microsoft-rooted code-signing certificates. Fox Tempest customers (Vanilla Tempest, Storm-0501, Storm-2561, Storm-0249) used these certificates to distribute Oyster (Broomstick) backdoors, Lumma Stealer, Vidar, and ransomware families including Rhysida, Akira, INC, Qilin, and BlackByte. The primary delivery vector is malvertising and SEO-poisoned download pages impersonating legitimate software (notably MSTeamsSetup.exe).

Two detection approaches are provided: (1) exact hash matching on known Fox Tempest-signed binaries disclosed by Microsoft DCU, and (2) execution of Microsoft Teams installer (MSTeamsSetup.exe) from paths inconsistent with legitimate deployment — a key indicator of the Vanilla Tempest malvertising chain. False positives for the hash-based detection: none expected (direct IOC match). False positives for the path-based detection: corporate software deployment tools (SCCM, Intune) staging installers in custom directories; suppress on known management tool parent processes.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Defense Evasion |
| Tactic ID | TA0005 |
| Technique | Subvert Trust Controls: Code Signing |
| Technique ID | T1553.002 |

Secondary techniques: T1036.001 (Masquerading: Invalid Code Signature), T1566.002 (Phishing: Spearphishing Link — via malvertising), T1598.003 (SEO Poisoning for initial delivery)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Installation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_hash IN (
      "f0668ce925f36ff7f3359b0ea47e3fa243af13cd6ad9661dfccc9ff79fb4f1cc",
      "11af4566539ad3224e968194c7a9ad7b596460d8f6e423fc62d1ea5fc0724326",
      "f0a6b89ec7eee83274cd484cea526b970a3ef28038799b0a5774bb33c5793b55"
  )
  by Processes.dest Processes.user Processes.process_name Processes.process_hash
     Processes.process Processes.parent_process_name Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=100
| table firstTime lastTime dest user parent_process_name process_name process_hash process risk_score
```

**Supplemental: Trojanized Teams installer from non-standard path (Vanilla Tempest malvertising)**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.process_name="MSTeamsSetup.exe" OR Processes.process_name="MSTeamsSetup_Win64.exe")
    AND NOT (Processes.process_path IN (
        "*\\AppData\\Local\\Microsoft\\Teams\\*",
        "*\\Program Files (x86)\\Microsoft\\Teams\\*",
        "*\\Program Files\\Microsoft\\Teams\\*"
    ))
    AND NOT Processes.parent_process_name IN ("msiexec.exe","sccmsetup.exe","ccmsetup.exe","IntuneManagementExtension.exe")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process_path Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_path, "(?i)\\\\Downloads\\\\|\\\\Desktop\\\\"), 85,
    match(process_path, "(?i)\\\\AppData\\\\Roaming\\\\|\\\\AppData\\\\Local\\\\Temp\\\\"), 80,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime dest user parent_process_name process_name process_path process risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Known Fox Tempest-signed hash (exact IOC match) | 100 | Confirmed malicious binary; no legitimate reason for execution |
| MSTeamsSetup.exe from Downloads or Desktop | 85 | Strongly indicative of malvertising delivery; Teams updates never land in user folders |
| MSTeamsSetup.exe from Roaming/Temp | 80 | High suspicion; Teams legitimate deployment paths are well-defined |
| MSTeamsSetup.exe from any other non-standard path | 70 | Suspicious; warrants investigation |

## Associated Threat Actors

| Actor | Relationship to Detection |
|-------|--------------------------|
| Fox Tempest | MSaaS operator; issued fraudulent Microsoft-rooted code-signing certificates to ransomware affiliates via Azure Artifact Signing; infrastructure disrupted by Microsoft DCU May 19 2026 |
| Vanilla Tempest (INC Ransomware members) | Primary Fox Tempest customer; distributes trojanized MSTeamsSetup.exe via malvertising delivering Oyster backdoor and Rhysida/INC ransomware |
| Storm-0501 | Confirmed Fox Tempest customer; associated with ransomware deployment |
| Storm-2561 | Confirmed Fox Tempest customer |
| Storm-0249 | Confirmed Fox Tempest customer |

## References

- [Microsoft Security Blog — Exposing Fox Tempest (2026-05-19)](https://www.microsoft.com/en-us/security/blog/2026/05/19/exposing-fox-tempest-a-malware-signing-service-operation/)
- [Microsoft On the Issues — Disrupting Fox Tempest (2026-05-19)](https://blogs.microsoft.com/on-the-issues/2026/05/19/disrupting-fox-tempest-a-cybercrime-service/)
- [BleepingComputer — Cybercrime service disrupted for abusing Microsoft platform to sign malware](https://www.bleepingcomputer.com/news/security/cybercrime-service-disrupted-for-abusing-microsoft-platform-to-sign-malware/)
- [MITRE ATT&CK — T1553.002 Subvert Trust Controls: Code Signing](https://attack.mitre.org/techniques/T1553/002/)
- [MITRE ATT&CK — T1036.001 Masquerading: Invalid Code Signature](https://attack.mitre.org/techniques/T1036/001/)
