# SprySOCKS — China-Linked Cross-Platform Backdoor (Windows Expansion)

**Source:** BleepingComputer, Elastic Security  
**Date:** 2026-06-16 (discovered); 2026-06-24 (analysis)  
**Attribution:** China-linked threat actor (suspected state-sponsored)  
**Status:** ACTIVE — new Windows variants (WIN_DRV, WIN_PLUS) discovered June 2026

## Summary

SprySOCKS is a backdoor previously known only on Linux platforms. June 2026 analysis revealed Windows variants with kernel-level rootkit capabilities. WIN_DRV uses a kernel driver to hide processes and network connections from userland tools; WIN_PLUS is a userland-only variant. The backdoor supports 30+ commands for reconnaissance and remote control.

## Variants

### Linux (original)
- Memory-resident backdoor
- Long-lived outbound TCP C2 on non-standard high port
- Process concealment via /proc manipulation

### WIN_DRV (Windows kernel variant)
- Installs an unsigned kernel driver from user-writeable path (AppData, ProgramData)
- Driver intercepts Windows kernel process enumeration (NtQuerySystemInformation)
- Hides SprySOCKS process and C2 network connection from tasklist, Process Explorer
- Achieves boot persistence via SCM driver service

### WIN_PLUS (Windows userland variant)
- No kernel driver; pure userland
- Uses COM hijacking or Run key for persistence
- DLL side-loading into legitimate Windows processes

## Capabilities (30+ commands)

- System reconnaissance (hostname, OS, IP, running processes)
- File system operations (read, write, delete, list)
- Process management (start, kill)
- Reverse shell
- Port forwarding / SOCKS proxy
- Screenshot capture
- Keylogging

## MITRE ATT&CK

| Technique | Description |
|-----------|-------------|
| T1014 | Rootkit (WIN_DRV kernel driver) |
| T1055 | Process Injection |
| T1071.001 | Application Layer Protocol: Web (C2) |
| T1543.003 | Create or Modify System Process: Windows Service (driver) |
| T1105 | Ingress Tool Transfer |
| T1059 | Command and Scripting Interpreter |

## Detection

Wazuh rules: 103609–103612

## Hunting Queries

- Windows Event 7045: new service of type "kernel driver" from non-system path
- Wazuh rootcheck alert for hidden process
- Suricata: long-lived TCP beaconing to non-HTTP/HTTPS ports from Windows workstations
- FIM: new .sys files in user-writeable directories
