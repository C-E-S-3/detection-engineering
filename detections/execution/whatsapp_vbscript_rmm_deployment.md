# WhatsApp VBScript RMM Deployment

## Description

Detects VBScript execution from user-writable paths (Downloads, AppData, Desktop) consistent with a
campaign distributing malicious `.vbs` attachments via WhatsApp and other messaging platforms. The
campaign — attributed with low confidence to a Chinese-speaking operator — uses VBScript files named
as invoices, bank statements, and payment records. Once executed, the script downloads secondary
payloads that bypass UAC via registry modification and deploy ManageEngine Endpoint Central as a
persistent RMM backdoor.

False positives: Legitimate business scripts deployed by IT that reside in user directories; power
users who run custom `.vbs` automation from Downloads. Tune by excluding known-good script hashes or
trusted parent processes (e.g., Group Policy deployment via gpscript.exe).

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Execution |
| Tactic ID | TA0002 |
| Technique | Command and Scripting Interpreter: Visual Basic |
| Technique ID | T1059.005 |
| Secondary Tactic | Defense Evasion |
| Secondary Technique | Abuse Elevation Control Mechanism: Bypass User Account Control |
| Secondary Technique ID | T1548.002 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Installation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where (Processes.process_name="wscript.exe" OR Processes.process_name="cscript.exe")
  AND (Processes.process="*.vbs*" OR Processes.process="*.vbe*")
  AND (Processes.process="*\\Downloads\\*"
    OR Processes.process="*\\AppData\\Roaming\\*"
    OR Processes.process="*\\AppData\\Local\\Temp\\*"
    OR Processes.process="*\\Desktop\\*")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(parent_process_name, "(?i)(whatsapp|telegram|signal|viber|wechat|line)"), 90,
    match(process, "(?i)(invoice|payment|statement|receipt|factura|rechnung|facture|talaan|hutang|bayar)"), 85,
    match(parent_process_name, "(?i)(chrome|firefox|msedge|iexplore|opera|brave)"), 80,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Parent process is a messaging app (WhatsApp, Telegram, Signal, etc.) | 90 | Near-certain malicious — legitimate scripts are not distributed via consumer messaging platforms |
| Script filename contains financial document keywords (invoice, payment, statement) | 85 | Strong indicator of social-engineering lure; matches WhatsApp campaign filenames |
| Parent process is a web browser | 80 | Suggests drive-by or web-based delivery; elevated suspicion |
| VBScript from user-writable path, other parent | 65 | Suspicious but possible for user automation; requires analyst review |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown (possibly Chinese-speaking; low confidence) — infrastructure overlap with ValleyRAT and Gh0st RAT | [Kaspersky Securelist — WhatsApp VBS RMM Campaign (2026-06-22)](https://securelist.com/whatsapp-vbs-rmm-campaign/120290/) |
| ValleyRAT (overlapping infrastructure) | [MITRE ATT&CK - ValleyRAT](https://attack.mitre.org/software/S1109/) |
| Gh0st RAT (overlapping infrastructure) | [MITRE ATT&CK - Gh0st RAT](https://attack.mitre.org/software/S0032/) |

## References

- [Kaspersky Securelist — An unknown actor distributes malicious VBS scripts via WhatsApp (2026-06-22)](https://securelist.com/whatsapp-vbs-rmm-campaign/120290/)
- [The Hacker News — WhatsApp VBScript Campaign Uses Fake Documents to Install ManageEngine RMM Tool (2026-06-22)](https://thehackernews.com/2026/06/whatsapp-vbscript-campaign-uses-fake.html)
- [BleepingComputer — WhatsApp phishing attack uses fake business docs to hack PCs (2026-06-22)](https://www.bleepingcomputer.com/news/security/whatsapp-phishing-attack-uses-fake-business-docs-to-hack-pcs/)
- [MITRE ATT&CK — T1059.005: Visual Basic](https://attack.mitre.org/techniques/T1059/005/)
- [MITRE ATT&CK — T1548.002: Bypass User Account Control](https://attack.mitre.org/techniques/T1548/002/)
- [MITRE ATT&CK — T1219: Remote Access Software](https://attack.mitre.org/techniques/T1219/)
