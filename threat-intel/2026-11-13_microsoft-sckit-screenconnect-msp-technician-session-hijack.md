---
title: "SCKit Malware Abuses ScreenConnect Run Command to Deploy RelayTrap and Steal MSP Technician Session Cookies"
date: 2026-11-13
source: "https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/"
tlp: WHITE
severity: HIGH
tags: [sckit, screenconnect, connectwise, msp, rmm, session-hijacking, relaytrap, cve-2026-84869, supply-chain, technician-targeting]
iocs_added: []
---

# SCKit Malware Abuses ScreenConnect Run Command to Deploy RelayTrap and Steal MSP Technician Session Cookies

## Summary

Microsoft's threat intelligence team documented an active campaign on November 13, 2026 in which attackers compromised cloud-hosted ConnectWise ScreenConnect panels and deployed **SCKit** malware across managed service provider (MSP) customer environments. SCKit includes a component called **RelayTrap** that replaces the legitimate ScreenConnect Guest client on target machines, enabling the attacker to intercept connecting technician sessions and steal authenticated management session cookies.

**Scope confirmed at time of publication:** 288 devices across 48 MSP customer organizations. All devices were compromised within approximately 90 minutes of initial access.

---

## Attack Chain

### Stage 1 — ScreenConnect Panel Takeover

Attackers gained access to cloud-hosted ScreenConnect partner portals. The exact initial access vector is debated:
- **CVE-2026-84869** (ConnectWise ScreenConnect file-transfer path traversal, patched in v26.6.5) is cited by some sources as the entry point.
- Huntress and Blackpoint Cyber stated they found no technical evidence linking CVE-2026-84869 to observed SCKit deployments. ConnectWise says no compromise of ConnectWise infrastructure was confirmed.
- ConnectWise disabled five third-party extensions across approximately 400 partner environments as a precaution; a compromised or malicious extension may be an alternative vector.

### Stage 2 — Run Command Payload Delivery

From the compromised ScreenConnect partner portal, attackers used ScreenConnect's built-in **Run Command** feature to execute SYSTEM-level commands on managed endpoints. Commands dropped a rogue installer:

```
C:\Windows\TEMP\sc.msi
```

The MSI was installed silently:

```
msiexec.exe /i C:\Windows\TEMP\sc.msi /quiet /qn
```

### Stage 3 — RelayTrap Installation

`sc.msi` installs **RelayTrap**, which replaces the legitimate ScreenConnect Guest client binary. RelayTrap functions as a man-in-the-middle layer for incoming technician support sessions:

- When a support technician connects to a managed device, RelayTrap intercepts the ScreenConnect session.
- It scans browser data stores and process memory for authenticated management console session cookies.
- Stolen cookies are exfiltrated to attacker infrastructure, enabling persistent access to the MSP management portal without credentials.

### Why This Attack Is Significant

This technique specifically targets **IT technicians** rather than the managed endpoints themselves. By compromising the RMM platform that technicians use to manage dozens or hundreds of organizations, a single successful session theft can pivot to the entire MSP customer base. This is a **supply chain / trusted tool abuse** pattern.

---

## MITRE ATT&CK

| Tactic | Technique | Description |
|--------|-----------|-------------|
| TA0001 Initial Access | T1190 | Exploit Public-Facing Application (ScreenConnect partner portal) |
| TA0002 Execution | T1072 | Software Deployment Tools (ScreenConnect Run Command as SYSTEM) |
| TA0002 Execution | T1218.007 | System Binary Proxy Execution: Msiexec (silent MSI install) |
| TA0003 Persistence | T1554 | Compromise Host Software Binary (RelayTrap replaces ScreenConnect Guest) |
| TA0006 Credential Access | T1539 | Steal Web Session Cookie (MSP management console session cookies) |
| TA0006 Credential Access | T1555.003 | Credentials from Web Browsers (browser session data) |
| TA0008 Lateral Movement | T1021.004 | Remote Services: RMM (pivot to MSP customers via stolen sessions) |

## Lockheed Martin Kill Chain

Exploitation → Installation (RelayTrap) → Actions on Objectives (session cookie theft → MSP portal takeover)

---

## Hunting Notes

**On managed endpoints:**
- `msiexec.exe` with `/quiet` or `/qn` flags spawned from `ScreenConnect.ClientService.exe` or `ScreenConnect.WindowsClient.exe`
- Files dropped to `C:\Windows\TEMP\sc.msi` or `C:\Windows\TEMP\sc*.msi`
- ScreenConnect processes spawning `cmd.exe` or `powershell.exe` with download commands

**On technician workstations:**
- ScreenConnect Guest client binary hash mismatch (compare against ConnectWise-signed reference)
- ScreenConnect processes reading browser credential/session storage paths
- Unexpected outbound network connections from ScreenConnect processes to non-ConnectWise infrastructure

---

## IOCs

No specific network IOCs (hashes, C2 IPs/domains) were publicly released by Microsoft or ConnectWise at time of writing. Huntress and Blackpoint Cyber published proprietary SCKit behavioral indicators through their platforms.

---

## References

- [Microsoft Security Blog — SCKit abuses ScreenConnect to deploy remote access and target technician sessions (Nov 13, 2026)](https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/)
- [BleepingComputer — New worm-like 'SCKit' malware targets MSPs in ScreenConnect attacks](https://www.bleepingcomputer.com/news/security/new-worm-like-sckit-malware-targets-msps-in-screenconnect-attacks/)
- [CybersecurityNews — Hackers Hijack ConnectWise ScreenConnect to Deploy SCKit Malware Across 288 Devices at 48 Organizations](https://cybersecuritynews.com/connectwise-screenconnect-hijacked/)
- [Lavx News — SCKit malware turns ScreenConnect support sessions into attack paths for MSPs](https://news.lavx.hu/article/sckit-malware-turns-screenconnect-support-sessions-into-attack-paths-for-msps)
- [CyberScoop — Rogue remote-access campaign spread through ScreenConnect add-on](https://cyberscoop.com/connectwise-screenconnect-sckit-attack)
- [Aviatrix AI — SCKit Malware Targets MSPs via ScreenConnect CVE-2026-84869](https://aviatrix.ai/threat-research-center/sckit-malware-screenconnect-msp-attacks-cve-2026-84869/)
