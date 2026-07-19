# DcRAT via Fake Indian Tax Filing Utility — Operation DragonReturn (China-Nexus)

## Description

Detects DcRAT (Dark Crystal RAT) deployment via a fake Indian Income Tax Department filing utility, attributed to a suspected China-nexus threat actor (Silver Fox TTP overlap) under the campaign name Operation DragonReturn. Active since May 18, 2026 and targeting the AY2026-27 ITR filing season, the campaign distributes a ZIP archive impersonating the Common Offline Utility that contains a trojanized installer. The installer drops background.jpg — a JPEG file containing the DcRAT payload hidden via LSB steganography — and executes a DLL side-loading chain to decrypt and load the payload in memory. AMSI is patched via .NET reflection to prevent detection of the in-memory .NET assembly. The payload injects into svchost.exe via CreateRemoteThread and establishes persistence as a Windows service named "MixedSvc" masquerading as "Windows Mixed Reality Service." Two parallel C2 channels are established: DcRAT over encrypted TLS to 223.26.63.40:2671 (ChinaNet ASN) and a Gh0st RAT variant to kkxqbh[.]top:6666.

Targets include corporate entities, tax professionals, chartered accountants, and individual taxpayers with organizational ties to India. As of June 17, 2026, the campaign remains fully active with all submissions confirmed from India.

Five detection signals are provided: (1) fake tax installer spawning a scripting interpreter, (2) PowerShell invoking bitmap steganography APIs, (3) AMSI bypass in PowerShell, (4) svchost.exe injection via CreateRemoteThread, and (5) network connections to confirmed Operation DragonReturn C2 infrastructure.

False positives: Indian tax software with scripting-based update mechanisms (extremely rare); security testing tools demonstrating AMSI bypass in a lab (suppress by hostname); EDR/AV engines creating threads in svchost.exe (tune rule 3 by adding EDR binary paths to exclusions).

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Execution, Defense Evasion, Persistence, Command and Control |
| Tactic ID | TA0002, TA0005, TA0003, TA0011 |
| Technique | User Execution: Malicious File; Obfuscated Files: Steganography; Process Injection; Create/Modify System Process: Windows Service; Masquerading; Impair Defenses: AMSI Bypass; Application Layer Protocol: Web Protocols |
| Technique ID | T1204.002, T1027.003, T1055, T1543.003, T1036.005, T1562.001, T1071.001 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Delivery |
| Exploitation |
| Installation |
| Command & Control (C2) |

## Splunk Detection Query

### Query 1: Fake Indian Tax Installer Spawning Child Interpreter

Detects the initial execution stage: trojanized Indian tax filing utility spawning cmd.exe, PowerShell, or other script interpreters — a behavior that legitimate Indian tax software never exhibits.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.parent_process_name IN (
    "ITRPrepPro.exe", "IncomeTax.exe", "IT_Offline_Utility.exe",
    "itr_offline.exe", "ITR_AY2026.exe", "income_tax_utility.exe",
    "IncomeTaxReturn.exe", "itr_filing_utility.exe", "offline_itr_utility.exe",
    "itr_prep.exe", "e-Filing.exe", "incometax_utility.exe")
  AND Processes.process_name IN (
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe",
    "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
    "certutil.exe", "bitsadmin.exe")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=80
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

### Query 2: PowerShell Bitmap Steganography Payload Extraction

Detects Stage 2 of the infection chain: PowerShell invoking System.Drawing bitmap APIs to extract the DcRAT payload hidden in background.jpg via LSB steganography.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name IN ("powershell.exe", "pwsh.exe")
  AND (Processes.process IN ("*GetPixel*", "*System.Drawing.Bitmap*",
    "*FromFile*jpg*", "*FromFile*png*", "*FromFile*bmp*",
    "*background.jpg*", "*.GetBitmap(*"))
by Processes.dest Processes.user Processes.process_name
   Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=70
| table firstTime lastTime dest user process_name process risk_score
```

### Query 3: AMSI Bypass via .NET Reflection in PowerShell

Detects Stage 3: PowerShell patching AmsiScanBuffer via .NET reflection to enable in-memory DcRAT .NET assembly loading without AV detection.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name IN ("powershell.exe", "pwsh.exe")
  AND (Processes.process IN (
    "*AmsiScanBuffer*", "*AmsiInitialize*", "*amsi.dll*",
    "*AmsiUtils*", "*GetDelegateForFunctionPointer*amsi*",
    "*Reflection.Assembly*Load(*", "*UnsafeNativeMethods*GetMethod*Amsi*"))
by Processes.dest Processes.user Processes.process_name
   Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85
| table firstTime lastTime dest user process_name process risk_score
```

### Query 4: DcRAT MixedSvc Persistence Service Installation

Detects Stage 5: DcRAT persistence as a Windows service named MixedSvc masquerading as "Windows Mixed Reality Service" but installed from a non-Microsoft path. Uses raw Windows System event log (no ES data model available for service installation events).

```spl
index=wineventlog source="WinEventLog:System" EventCode=7045
(ServiceName="MixedSvc" OR ServiceName="*Mixed*Reality*" OR ServiceName="*MixedSvc*")
NOT (ServiceBinaryPathName="C:\\Windows\\System32\\*"
  OR ServiceBinaryPathName="C:\\Program Files\\WindowsApps\\MicrosoftCorporation*MixedReality*")
| eval risk_score=95
| table _time ComputerName ServiceName ServiceType ServiceBinaryPathName risk_score
```

### Query 5: Network Connections to Operation DragonReturn C2 Infrastructure

Detects Stage 6: outbound connections to the confirmed DcRAT C2 IP (223.26.63.40) and associated domains for Gh0st RAT, AsyncRAT, and supplemental C2 channels.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.dest="223.26.63.40"
  OR All_Traffic.dest_host IN ("kkxqbh.top", "ouewop.com", "1kkkkddd.com")
by All_Traffic.src All_Traffic.dest All_Traffic.dest_host All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=100
| table firstTime lastTime src dest dest_host dest_port app risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Indian tax utility parent spawning cmd/PowerShell/mshta/rundll32 | 80 | Legitimate tax utilities never spawn scripting engines; high-confidence trojanized installer execution |
| PowerShell invoking System.Drawing Bitmap GetPixel or FromFile with image extension | 70 | Steganographic payload extraction pattern; legitimate admin scripts very rarely use bitmap APIs; correlate with Query 1 for 90+ confidence |
| PowerShell referencing AmsiScanBuffer, AmsiUtils, or combined GetDelegateForFunctionPointer+amsi | 85 | AMSI bypass is not a legitimate admin operation; near-certain malicious intent; confirms in-memory payload loading |
| Windows service "MixedSvc" installed from non-Microsoft path | 95 | Confirmed DcRAT persistence mechanism; legitimate Windows Mixed Reality service is pre-installed by Windows Update and does not trigger EventID 7045 from a custom path |
| Network connection to 223.26.63.40, kkxqbh.top, ouewop.com, or 1kkkkddd.com | 100 | Direct IOC match; all four attributed exclusively to Operation DragonReturn by Seqrite as of 2026-06-17; sustained beaconing (2+ events/120s) confirms active RAT |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Suspected China-nexus (Silver Fox overlap) — Operation DragonReturn | [Seqrite — Operation DragonReturn (2026-07)](https://www.seqrite.com/blog/operation-dragonreturn-china-nexus-cyber-espionage-campaign-targeting-govt-of-india-mof-tax-infrastructure-via-multi-stage-dcrat-deployment/) |
| DcRAT (Dark Crystal RAT) — commodity malware used by multiple China-aligned actors | [Broadcom — DCRat (Dark Crystal RAT) Trojan](https://www.broadcom.com/support/security-center/protection-bulletin/dcrat-aka-dark-crystal-rat-trojan-malware) |
| Silver Fox — Chinese cybercrime group with TTP overlap identified by Seqrite | [The Hacker News — Operation DragonReturn (2026-07)](https://thehackernews.com/2026/07/suspected-china-nexus-hackers-use-fake.html) |

## References

- [The Hacker News — Suspected China-Nexus Hackers Use Fake Indian Tax Filing Utility to Deploy DcRAT (2026-07)](https://thehackernews.com/2026/07/suspected-china-nexus-hackers-use-fake.html)
- [Seqrite — Operation DragonReturn: China-Nexus Cyber Espionage Campaign Targeting GoI Tax Infrastructure (2026-07)](https://www.seqrite.com/blog/operation-dragonreturn-china-nexus-cyber-espionage-campaign-targeting-govt-of-india-mof-tax-infrastructure-via-multi-stage-dcrat-deployment/)
- [Cyderes — Tax Trap: Fake Indian ITR Notice to Dual RAT Deployment in Six Stages](https://www.cyderes.com/howler-cell/fake-indian-itr-notice-dual-rat-deployment)
- [CSO Online — Cybercriminals exploit India's tax filing season with a dual-malware campaign](https://www.csoonline.com/article/4194440/cybercriminals-exploit-indias-tax-filing-season-with-a-dual-malware-campaign.html)
- [DcRAT deep dive — muha2xmad (malware analysis)](https://muha2xmad.github.io/malware-analysis/dcrat/)
- [Splunk — DarkCrystal RAT Analytics Story](https://research.splunk.com/stories/darkcrystal_rat/)
- [MITRE ATT&CK — T1204.002: User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
- [MITRE ATT&CK — T1055: Process Injection](https://attack.mitre.org/techniques/T1055/)
- [MITRE ATT&CK — T1543.003: Windows Service](https://attack.mitre.org/techniques/T1543/003/)
- [MITRE ATT&CK — T1027.003: Steganography](https://attack.mitre.org/techniques/T1027/003/)
- [MITRE ATT&CK — T1562.001: Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)
