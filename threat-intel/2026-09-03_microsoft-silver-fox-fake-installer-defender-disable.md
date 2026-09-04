---
scraped_at: 2026-09-04T00:00:00Z
source_url: https://www.microsoft.com/en-us/security/blog/2026/09/03/silver-fox-fake-installer-campaign-disables-windows-update-deploys-ghost-rat/
report_type: threat-intel
severity: high
title: "Silver Fox (Yinhu) Fake Installer Campaign: Windows Update/Defender Impairment and Gh0st RAT/ValleyRAT Deployment"
---

# Silver Fox (Yinhu) Fake Installer Campaign: Windows Update/Defender Impairment and Gh0st RAT/ValleyRAT Deployment

## Summary

Microsoft Threat Intelligence published research on an active campaign by Silver Fox (also tracked as Yinhu), a Chinese-speaking threat cluster. The campaign delivers trojanized software installer ZIP archives via the domain `gehie246[.]com` and related infrastructure. When executed, the malicious MSI disables Windows Update, configures Windows Defender exclusions for its installation directory, deletes Volume Shadow Copies (inhibiting recovery), and establishes scheduled task persistence running as SYSTEM. The final payload is Gh0st RAT or ValleyRAT (also called WinOS 4.0), providing full remote access. This campaign is consistent with Silver Fox's historical pattern of targeting Chinese-speaking users and Chinese-diaspora businesses in Southeast Asia.

## Threat Actor

| Field | Value |
|-------|-------|
| Name | Silver Fox (Microsoft designation); also Yinhu |
| Origin | China (PRC-linked; primary targeting of Chinese-speaking communities) |
| Targets | Chinese-speaking users and businesses; Southeast Asian Chinese diaspora; financial sector |
| Motivation | Espionage and financial fraud; full remote access for follow-on collection |
| Tools | Gh0st RAT, ValleyRAT (WinOS 4.0) |

## Attack Chain

```
gehie246[.]com → ZIP download (fake installer)
    → Extract MSI → msiexec.exe /i <payload>.msi
        → Stop Windows Update service (wuauserv)
        → Disable Windows Update service (start=disabled)
        → Add Defender exclusion (Add-MpPreference -ExclusionPath)
        → Delete VSS snapshots (vssadmin delete shadows /all /quiet)
        → Install scheduled task (SYSTEM context, runs at logon)
            → Launch Gh0st RAT or ValleyRAT (WinOS 4.0)
                → C2 beacon to attacker infrastructure
```

## Technical Details

### Delivery
- Distribution domain: `gehie246[.]com`
- Lure: Trojanized ZIP archives named after popular Chinese business/productivity software (e.g., accounting tools, ERP clients, productivity suites)
- Execution: Victim runs installer; malicious MSI invoked via `msiexec.exe /i <file>.msi`

### Defense Impairment Sequence (run as SYSTEM via MSI custom action)

| Action | Command / Method |
|--------|-----------------|
| Stop Windows Update | `net stop wuauserv` |
| Disable Windows Update | `sc config wuauserv start= disabled` |
| Add Defender Exclusion | `Add-MpPreference -ExclusionPath <install_dir>` via PowerShell |
| Delete VSS Snapshots | `vssadmin delete shadows /all /quiet` |
| Create Scheduled Task | `schtasks /create /sc ONLOGON /rl HIGHEST /ru SYSTEM /tn <name> /tr <payload>` |

### Payloads

| Payload | Notes |
|---------|-------|
| Gh0st RAT | Open-source Chinese RAT; widely used by multiple threat actors; full remote access, keylogging, screen capture |
| ValleyRAT (WinOS 4.0) | Modular RAT attributed to Silver Fox; plugin architecture; targets financial data and credentials |

## IOCs

### Domains (added to iocs/domain.csv)

| Indicator | Context |
|-----------|---------|
| `gehie246[.]com` | Silver Fox fake installer delivery domain; distributes ZIP archives containing malicious MSI |

No IP addresses or file hashes confirmed in public reporting at time of ingestion.

## Detection Guidance

A dedicated Splunk detection has been created for the combined defense impairment pattern:

`detections/defense_evasion/silver_fox_defender_windows_update_impairment.md`

### Key Signals

- `msiexec.exe` spawning `cmd.exe` or `powershell.exe` as a child process
- `net.exe stop wuauserv` or `sc.exe config wuauserv start= disabled` from an installer parent
- `Add-MpPreference -ExclusionPath` from a SYSTEM-context process
- `vssadmin.exe delete shadows` execution
- New scheduled task creation by an MSI installer process running as SYSTEM
- Outbound connections from `gehie246[.]com` or resolved IPs in web/DNS logs

## MITRE ATT&CK

| Tactic | Technique | ID |
|--------|-----------|-----|
| Initial Access | Phishing: Spearphishing Link / User Execution | T1566.002 / T1204.002 |
| Execution | System Services: Service Execution (msiexec) | T1569.002 |
| Persistence | Scheduled Task/Job: Scheduled Task | T1053.005 |
| Defense Evasion | Impair Defenses: Disable or Modify Tools | T1562.001 |
| Defense Evasion | Impair Defenses: Disable or Modify System Firewall | T1562.004 |
| Impact | Inhibit System Recovery (VSS deletion) | T1490 |
| Command and Control | Application Layer Protocol | T1071 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Delivery |
| Exploitation |
| Installation |
| Command & Control |

## References

- [Microsoft — Silver Fox Fake Installer Campaign](https://www.microsoft.com/en-us/security/blog/2026/09/03/silver-fox-fake-installer-campaign-disables-windows-update-deploys-ghost-rat/)
- [MITRE ATT&CK G0049 — Silver Fox / Yinhu group tracking](https://attack.mitre.org/groups/)
- [MITRE ATT&CK T1562.001 — Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)
- [MITRE ATT&CK T1490 — Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)
- [ValleyRAT / WinOS 4.0 Technical Analysis — previous reporting](https://www.fortinet.com/blog/threat-research/valleyrat-new-malware-targeting-chinese-speakers)
