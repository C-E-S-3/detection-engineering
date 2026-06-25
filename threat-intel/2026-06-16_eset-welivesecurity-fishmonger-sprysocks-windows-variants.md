---
scraped_at: 2026-06-19T00:00:00Z
source_url: https://www.welivesecurity.com/en/eset-research/fishmongers-arsenal-upgraded-sprysocks-windows/
report_type: threat-intel
severity: high
title: "FishMonger (Earth Lusca) Expands SprySOCKS Backdoor to Windows With Kernel Rootkit and Print Processor Persistence"
---

## 1. IOCs

### IP Addresses

| Indicator | Type | Notes |
|-----------|------|-------|
| `207.148.78[.]36` | C2 IP | WIN_PLUS hardcoded C2; Vultr AS20473; TCP:443, UDP:53, WS:80 |
| `207.148.75[.]122` | Delivery/staging IP | Delivery server observed in June 2023 FishMonger campaign; same Vultr /20 block |

### File Indicators

| Indicator | Type | Notes |
|-----------|------|-------|
| `fsdiskbit.sys` | Filename | DriverLoader kernel driver; signed with leaked PastDSE certificate; loads RawWNPF |
| `KX1B5206BDC1743DD.dat` | Filename | Encrypted DriverLoader container (AES-128-ECB) written to spool directories |
| `KW1B5206BDC1743FP.dat` | Filename | RawWNPF kernel driver blob loaded in-memory by DriverLoader; provides rootkit functionality |
| `VSPMsg` | Registry value name | Malicious WIN_PLUS Print Processor DLL registered under Print Processors key |

## 2. TTPs — MITRE ATT&CK

| Tactic | Technique ID | Technique Name | FishMonger Usage |
|--------|-------------|----------------|-----------------|
| Defense Evasion | T1014 | Rootkit | RawWNPF kernel driver hides processes, files, registry keys, and network connections from security tools and administrators |
| Defense Evasion | T1562.001 | Impair Defenses: Disable or Modify Tools | Kernel-level rootkit functionality prevents EDR visibility into SprySOCKS activity |
| Persistence | T1547.012 | Boot or Logon Autostart Execution: Print Processors | WIN_PLUS registers `VSPMsg` as a custom Print Processor DLL under `HKLM\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Print Processors\VSPMsg` |
| Persistence | T1546.012 | Event Triggered Execution: Image File Execution Options Injection | WIN_DRV achieves persistence via IFEO on `vds.exe` |
| Persistence | T1053.005 | Scheduled Task/Job: Scheduled Task | WIN_DRV additionally creates a scheduled task for redundant persistence |
| Execution | T1055 | Process Injection | WIN_PLUS uses doppelgänging-like injection to load backdoor into `svchost.exe` via the Print Spooler service |
| Command and Control | T1095 | Non-Standard Port / Multi-Protocol | SprySOCKS C2 over TCP:443, UDP:53, and WebSocket:80 simultaneously |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | WebSocket channel used for C2 traffic to blend with web traffic |

## 3. Malware & Tools

### SprySOCKS (v1.8) — Windows Variants

SprySOCKS is a cross-platform backdoor attributed to FishMonger. Originally documented as a Linux implant (ESET research, 2023), v1.8 introduces two undocumented Windows variants:

**WIN_DRV (Advanced variant)**
- Loads `fsdiskbit.sys` (DriverLoader) signed with a leaked certificate from the PastDSE GitHub repository
- DriverLoader decrypts and memory-loads `KW1B5206BDC1743FP.dat` (RawWNPF), a kernel-mode rootkit driver
- RawWNPF intercepts Windows API calls to hide: active network connections on the backdoor's port, running SprySOCKS processes, backdoor files on disk, and malicious registry entries
- Persistence: IFEO injection on `vds.exe` + scheduled task (dual-path redundancy)
- Creates a passive TCP backdoor that activates only when specifically crafted data is received, reducing network noise

**WIN_PLUS (Lighter variant)**
- No kernel driver; relies on Print Spooler service for persistence and injection
- Registers a malicious DLL as a custom Print Processor named `VSPMsg` under Windows Print Environments
- Windows Print Spooler (`spoolsv.exe`) loads `VSPMsg` at service startup, injecting the backdoor into `svchost.exe`
- Uses AES-128-ECB decryption (hardcoded key) on encrypted DLL payloads stored in spool directories
- Hardcoded C2: `207.148.78[.]36` on TCP:443, UDP:53, and WebSocket:80

Both variants implement 30+ backdoor commands including file system operations, process management, credential access, and network tunneling.

## 4. Threat Actor / Campaign Attribution

**Actor:** FishMonger (also tracked as Earth Lusca, TAG-22, Aquatic Panda, Red Dev 10)
**Umbrella:** Winnti Group
**Nexus:** People's Republic of China (PRC)
**Operator:** Assessed with high confidence to be operated by I-SOON (Anxun Information Technology Co., Ltd.), a Chinese cybersecurity contractor based in Chengdu whose internal communications leaked in early 2024.

**Targeting:** Government organizations in Honduras, Taiwan, Thailand, and Pakistan. Campaign aligns with PRC strategic intelligence interests in diplomatic and political targets.

**Activity Timeline:** ESET telemetry documents SprySOCKS Windows activity between 2023 and 2024. Research published June 16, 2026.

**MITRE ATT&CK Group:** [FishMonger / Earth Lusca (G0010)](https://attack.mitre.org/groups/G0010/)

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Registry
where Registry.registry_path="*\\Control\\Print\\Environments\\*\\Print Processors\\*"
  AND Registry.registry_value_name="Driver"
by Registry.dest Registry.user Registry.registry_path Registry.registry_value_name Registry.registry_value_data
| `drop_dm_object_name(Registry)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| where risk_score >= 75
| table firstTime lastTime dest user registry_path registry_value_name registry_value_data risk_score
```
*Detects malicious Print Processor DLL registration — WIN_PLUS SprySOCKS persistence mechanism (T1547.012). Legitimate Print Processor installs are rare outside of dedicated print server builds; any new `Driver` value under `Print Processors\` in user environments is high-confidence suspicious.*

```spl
`sysmon` EventCode=6
(ImageLoaded="*fsdiskbit.sys*" OR ImageLoaded="*KW1B5206BDC1743FP.dat*" OR ImageLoaded="*KX1B5206BDC1743DD.dat*")
| stats count min(_time) as firstTime max(_time) as lastTime by Computer, ImageLoaded, Signature, SignatureStatus, Hashes
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime Computer ImageLoaded Signature SignatureStatus Hashes risk_score
```
*Detects kernel driver load events (Sysmon EID 6) for SprySOCKS WIN_DRV rootkit components. `fsdiskbit.sys` (DriverLoader) and the RawWNPF payload file are unique to this malware family. The leaked PastDSE certificate used to sign fsdiskbit.sys may also show as `Expired` or `Revoked` in SignatureStatus.*

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where (Processes.parent_process_name="spoolsv.exe" AND Processes.process_name="svchost.exe")
  OR (Processes.process_name="vds.exe" AND Processes.parent_process_name!="services.exe")
by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    parent_process_name=="spoolsv.exe" AND process_name=="svchost.exe", 75,
    process_name=="vds.exe" AND parent_process_name!="services.exe", 80,
    1=1, 50)
| where risk_score >= 75
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```
*Detects anomalous process relationships associated with SprySOCKS injection chains: (1) `spoolsv.exe` spawning `svchost.exe` indicates WIN_PLUS Print Processor injection; (2) `vds.exe` started by anything other than `services.exe` indicates WIN_DRV IFEO hijack. Both are unusual in normal environments.*

```spl
index=network (dest_ip="207.148.78.36" OR dest_ip="207.148.75.122")
| stats count min(_time) as firstTime max(_time) as lastTime by src_ip, dest_ip, dest_port, protocol
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src_ip dest_ip dest_port protocol risk_score
```
*Direct IOC match for SprySOCKS WIN_PLUS C2 (`207.148.78.36`) and campaign delivery infrastructure (`207.148.75.122`). Both on Vultr AS20473 in the 207.148.64.0/20 block.*

## 6. Executive Summary

ESET disclosed on June 16, 2026, that FishMonger — a China-nexus cyberespionage group operated by I-SOON contractors — has expanded its SprySOCKS backdoor arsenal to include two previously undocumented Windows variants (WIN_DRV and WIN_PLUS). While telemetry from these variants dates to 2023–2024, their existence was unknown to the security community until this disclosure.

The more sophisticated WIN_DRV variant deploys a kernel rootkit (RawWNPF, loaded via `fsdiskbit.sys`) that hides the backdoor's processes, files, registry entries, and network connections from all userland-based security tools, including EDRs. It achieves dual-path persistence through IFEO injection on `vds.exe` and a scheduled task. The lighter WIN_PLUS variant exploits the Windows Print Spooler service to load a malicious DLL via a custom Print Processor registration, injecting into `svchost.exe`.

Both variants communicate over three simultaneous channels (TCP:443, UDP:53, WebSocket:80) and support 30+ backdoor commands. The C2 IP `207.148.78[.]36` (Vultr) is hardcoded in WIN_PLUS samples.

Organizations hosting government data or involved in diplomacy — particularly in Taiwan, Southeast Asia, or Latin America — should review for indicators of FishMonger/Earth Lusca targeting. Priority detections: Print Processor registry modifications, fsdiskbit.sys kernel driver loads (Sysmon EID 6), and connections to the documented C2 IPs.

## References

- [ESET — FishMonger's arsenal upgraded: SprySOCKS for Windows (2026-06-16)](https://www.welivesecurity.com/en/eset-research/fishmongers-arsenal-upgraded-sprysocks-windows/)
- [GlobeNewswire — ESET Research press release (2026-06-16)](https://www.globenewswire.com/news-release/2026/06/16/3312329/0/en/eset-research-china-aligned-fishmonger-updates-its-arsenal-targets-governments-in-asia-and-latin-america.html)
- [The Hacker News — China-Linked SprySOCKS Backdoor Expands to Windows (2026-06-16)](https://thehackernews.com/2026/06/china-linked-sprysocks-backdoor-expands.html)
- [BleepingComputer — Windows version of SprySOCKS Linux malware used to attack govt orgs (2026-06-16)](https://www.bleepingcomputer.com/news/security/windows-version-of-sprysocks-linux-malware-used-to-attack-govt-orgs/)
- [Security Affairs — China-Linked FishMonger Ports SprySOCKS to Windows (2026-06-16)](https://securityaffairs.com/193728/apt/china-linked-fishmonger-ports-sprysocks-to-windows-with-kernel-level-stealth-and-uefi-bootkit-hints.html)
- [MITRE ATT&CK — FishMonger / Earth Lusca (G0010)](https://attack.mitre.org/groups/G0010/)
- [MITRE ATT&CK — T1547.012 Print Processors](https://attack.mitre.org/techniques/T1547/012/)
- [MITRE ATT&CK — T1014 Rootkit](https://attack.mitre.org/techniques/T1014/)
