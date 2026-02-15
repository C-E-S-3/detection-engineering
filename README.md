# Detection Engineering

Collection of Splunk detection rules organized by MITRE ATT&CK tactic, with risk scoring, threat actor mapping, and Lockheed Martin Kill Chain alignment.

---

## Repository Structure

```
CLAUDE.md                          # Guide for adding new detections
detections/
├── _template.md                   # Detection file template
├── initial_access/                # TA0001 - Phishing, SEO poisoning, drive-by
├── execution/                     # TA0002 - PowerShell, WMI, scripting, LOLBAS
├── persistence/                   # TA0003 - Scheduled tasks, registry
├── defense_evasion/               # TA0005 - Rundll32, DLL sideloading, obfuscation
├── credential_access/             # TA0006 - Credential dumping
├── lateral_movement/              # TA0008 - SMB/WMI exec, admin shares
├── command_and_control/           # TA0011 - C2 beaconing, DNS, WordPress C2
├── collection/                    # TA0009 - Cryptocurrency targeting
└── impact/                        # TA0040 - Ransomware, data destruction
threat_intel/
└── gootloader_ttp_analysis.md     # Gootloader full kill chain TTP analysis
```

## Getting Started

To add a new detection, see [CLAUDE.md](CLAUDE.md) for the full guide.

Quick steps:
1. Copy `detections/_template.md` to the appropriate category folder
2. Fill in description, MITRE mapping, Kill Chain phase, and SPL query
3. Update the category `README.md` with the new detection

## Threat Actor Coverage

| Threat Actor | Type | Detections | Key Techniques |
|-------------|------|------------|----------------|
| [Gootloader / UNC2565](https://attack.mitre.org/software/S1138/) | Malware Loader | 13 | SEO poisoning, JS execution, registry stuffing, fileless PowerShell, HTTPS C2 |
| [Lazarus Group (HIDDEN COBRA)](https://attack.mitre.org/groups/G0032/) | Nation-State APT (DPRK) | 11 | Spearphishing, LOLBAS, DLL sideloading, DGA, cryptocurrency theft |
| [Medusa Ransomware](https://attack.mitre.org/software/S1131/) | Ransomware Operator | 2 | Invoke-SMBExec/WMIExec lateral movement, credential dumping |

## Detection Categories

| Category | Count | Description |
|----------|-------|-------------|
| [Initial Access](detections/initial_access/) | 3 | SEO poisoning downloads, JS file creation, O365 spearphishing |
| [Execution](detections/execution/) | 9 | PowerShell, WMI, wscript, encoded commands, process chains |
| [Persistence](detections/persistence/) | 2 | Registry stuffing, scheduled task creation |
| [Defense Evasion](detections/defense_evasion/) | 5 | RunDLL abuse, LOLBAS, DLL sideloading, proxy execution |
| [Command and Control](detections/command_and_control/) | 6 | HTTPS beaconing, DNS anomalies, WordPress C2, DGA |
| [Lateral Movement](detections/lateral_movement/) | 2 | SMB/WMI exec, admin share access, credential dumping |
| [Collection](detections/collection/) | 1 | Cryptocurrency wallet/exchange targeting |
| [Credential Access](detections/credential_access/) | 0 | (placeholder for future detections) |
| [Impact](detections/impact/) | 0 | (placeholder for future detections) |

## Data Sources

Detections use these Splunk ES data models and source macros:

| Data Source | Type | Used By |
|------------|------|---------|
| `Endpoint.Processes` | ES Data Model | Process execution, command lines, parent-child chains |
| `Endpoint.Filesystem` | ES Data Model | File creation and modification events |
| `Endpoint.Registry` | ES Data Model | Registry key/value modifications |
| `Network_Traffic.All_Traffic` | ES Data Model | Firewall and network connection data |
| `Network_Resolution.DNS` | ES Data Model | DNS query and response data |
| `Web.Web` | ES Data Model | HTTP/HTTPS request data |
| `` `crowdstrike` `` | Source Macro | CrowdStrike EDR raw events |
| `` `o365` `` | Source Macro | Office 365 management activity |
| `` `fortigate` `` | Source Macro | Fortigate firewall logs |
| `` `infoblox_dns` `` | Source Macro | Infoblox DNS logs |
| `` `zscaler_dns` `` | Source Macro | Zscaler DNS logs |
