# Twill Typhoon FDMTP Backdoor DLL Sideloading via QuickFox Supply Chain

## Description

Detects DLL sideloading execution patterns associated with the **FDMTP backdoor** delivered via the trojanized QuickFox VPN installer (versions 3.51.0–3.55.5). Twill Typhoon (significant tooling overlap with Mustang Panda / RedDelta) compromised the QuickFox software supply chain to bundle a malicious DLL alongside a legitimate signed helper executable. On installer launch, the OS loader resolves the malicious DLL before the system path.

The detection targets: (1) QuickFox processes spawning unexpected child processes, (2) DLL loads from QuickFox installation directories by non-QuickFox processes, and (3) outbound connections to known FDMTP C2 domains and port range 20800–20816.

**False positives:** Legitimate QuickFox usage on hosts where the software is authorized. Baseline QuickFox parent–child process relationships before deploying. The C2 domain IOCs and port-range rules have very low false positive potential.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Defense Evasion |
| Tactic ID | TA0005 |
| Technique | Hijack Execution Flow: DLL Side-Loading |
| Technique ID | T1574.002 |

Secondary techniques: T1195.002 (Supply Chain Compromise), T1573.001 (Encrypted Channel: Symmetric Cryptography)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Installation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.process_name="QuickFox.exe" OR Processes.parent_process_name="QuickFox.exe")
    AND NOT Processes.process_name IN ("QuickFox.exe","QuickFoxHelper.exe","QuickFoxUpdater.exe")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_name,"(?i)(cmd|powershell|wscript|cscript|mshta|regsvr32|rundll32)\.exe"), 90,
    match(process_name,"(?i)(schtasks|sc|net|reg)\.exe"), 75,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score
```

### FDMTP C2 Domain Lookup

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Resolution.DNS
  where DNS.query IN ("www.icloud-cdn.net","www.google-apis.net","icloud-cdn.net","google-apis.net")
  by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime src query answer risk_score
```

### FDMTP Custom Protocol — Outbound TCP 20800–20816

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_port>=20800 AND All_Traffic.dest_port<=20816
    AND All_Traffic.direction="outbound"
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    app IN ("unknown","tcp"), 85,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime src dest dest_port app risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| QuickFox spawns cmd/powershell/wscript/mshta/regsvr32/rundll32 | 90 | High-confidence lateral movement/loader execution — not expected from VPN software |
| QuickFox spawns persistence tools (schtasks, sc, reg, net) | 75 | Persistence setup from VPN parent is suspicious |
| Any other unexpected child of QuickFox | 60 | Anomalous process tree; warrants investigation |
| DNS resolution of FDMTP C2 domains | 90 | Known malicious domains with no legitimate use |
| Outbound TCP to port range 20800–20816 (unknown/tcp app) | 85 | Non-standard port range with no known benign application |
| Outbound TCP to port range 20800–20816 (other app) | 70 | Lower confidence but still worth reviewing |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Twill Typhoon (Mustang Panda / RedDelta / TA416 / BRONZE PRESIDENT) | [MITRE ATT&CK G0129](https://attack.mitre.org/groups/G0129/) |

## References

- [Fortinet Threat Research — QuickFox Supply Chain Attack FDMTP](https://www.fortinet.com/blog/threat-research/quickfox-supply-chain-attack-used-to-deploy-fdmtp-implant)
- [MITRE ATT&CK — T1574.002: Hijack Execution Flow: DLL Side-Loading](https://attack.mitre.org/techniques/T1574/002/)
- [MITRE ATT&CK — T1195.002: Supply Chain Compromise: Software Supply Chain](https://attack.mitre.org/techniques/T1195/002/)
- [MITRE ATT&CK — Twill Typhoon / Mustang Panda (G0129)](https://attack.mitre.org/groups/G0129/)
- [Threat Intel Report — threat-intel/2026-08-05_fortinet-quickfox-fdmtp-supply-chain-twill-typhoon.md](../../threat-intel/2026-08-05_fortinet-quickfox-fdmtp-supply-chain-twill-typhoon.md)
