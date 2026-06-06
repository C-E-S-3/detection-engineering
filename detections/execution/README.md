# Execution Detections

**MITRE ATT&CK Tactic:** [Execution (TA0002)](https://attack.mitre.org/tactics/TA0002/)
**Kill Chain Phase:** Exploitation

Detections for techniques adversaries use to run malicious code on a local or remote system, including abuse of command interpreters, scripting engines, and system binaries.

---

## Detections

| Detection | MITRE Technique | Description |
|-----------|----------------|-------------|
| [Gootloader Wscript JS Execution](gootloader_wscript_js_execution.md) | T1059.007 | Wscript executing JavaScript from user download/temp directories |
| [Gootloader Wscript Spawning PowerShell](gootloader_wscript_spawning_powershell.md) | T1059.001 | Wscript spawning PowerShell or cscript child process |
| [Gootloader PowerShell Registry Decode](gootloader_powershell_registry_decode.md) | T1059.001 | PowerShell reading and decoding payloads stored in registry |
| [Gootloader PowerShell Encoded Command](gootloader_powershell_encoded_command.md) | T1059.001, T1027 | PowerShell execution with abnormally long encoded command lines |
| [Gootloader Full Kill Chain Correlation](gootloader_full_killchain_correlation.md) | T1059.007, T1059.001 | Correlated wscript-to-powershell execution chain on a single host |
| [Godloader Godot Engine .pck Execution](godloader_godot_engine_pck_execution.md) | T1059, T1129, T1036 | Godot game engine loading malicious .pck files and spawning PowerShell for payload delivery |
| [Suspicious PowerShell Risk Rule](suspicious_powershell_risk_rule.md) | T1059.001 | Composite risk scoring for suspicious PowerShell execution patterns |
| [WMI Command Execution](wmi_command_execution.md) | T1047 | WMI-based command execution via wmic.exe or scrcons.exe |
| [Lazarus Encoded Command Execution](lazarus_encoded_command_execution.md) | T1059.001, T1027 | Encoded PowerShell and script interpreter command execution |
| [Lazarus EDR Detection](lazarus_edr_detection.md) | T1059, T1218 | Multi-technique detection via CrowdStrike EDR for Lazarus TTPs |
| [ClickFix User Execution Lure](clickfix_user_execution_lure.md) | T1204.002, T1059.001, T1218.005 | PowerShell/mshta spawned from browser or Windows Run dialog; fake CAPTCHA and ClickFix-style clipboard execution lures (57.5% of intrusions per Blackpoint 2026) |
| [CIFSwitch Linux Local Privilege Escalation via cifs.spnego Key Forgery](cifswitch_linux_cifs_spnego_privilege_escalation.md) | T1068, T1059.006 | 19-year-old Linux kernel LPE (CVE pending, May 2026); Python3 PoC forges cifs.spnego key requests to gain deterministic root access on AlmaLinux 9, Rocky Linux 9, CentOS Stream 9, Linux Mint, Kali Linux, and SLES 15 |
| [Cisco SD-WAN Manager CLI Command Injection (CVE-2026-20245)](cisco_sdwan_cve_2026_20245_command_injection_priv_escalation.md) | T1059.004, T1068 | CVE-2026-20245 zero-day (CVSS 7.8, no patch); authenticated netadmin uploads crafted file triggering OS command injection as root; `/var/log/scripts.log` forensic detection + SD-WAN service process spawning shell children; natural escalation chain from CVE-2026-20182 auth bypass |

---

## Threat Actors

| Actor | Type | TTPs | References |
|-------|------|------|-----------|
| Gootloader / UNC2565 | Malware Loader | Wscript execution of obfuscated JS, PowerShell fileless execution from registry | [MITRE - Gootloader (S1138)](https://attack.mitre.org/software/S1138/), [HP Wolf Security - Gootloader Analysis](https://threatresearch.ext.hp.com/gootloader-inside-out/) |
| Godloader / GodLoader (Stargazer Goblin) | Malware Loader | Godot game engine abuse via malicious .pck files, PowerShell for Defender evasion and payload download | [Check Point - Gaming Engines: An Undetected Playground](https://research.checkpoint.com/2024/gaming-engines-an-undetected-playground-for-malware-loaders/), [Check Point - Stargazers Ghost Network](https://research.checkpoint.com/2024/stargazers-ghost-network/) |
| Lazarus Group (HIDDEN COBRA) | Nation-State APT (DPRK) | Living-off-the-land binaries, encoded PowerShell, certutil/bitsadmin abuse | [MITRE - Lazarus Group (G0032)](https://attack.mitre.org/groups/G0032/), [CISA - AppleJeus](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-048a) |
| Medusa Ransomware | Ransomware Operator | PowerShell-based WMI/SMB execution for lateral movement | [MITRE - Medusa](https://attack.mitre.org/software/S1131/), [CISA - StopRansomware: Medusa](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a) |
| Scattered Spider / EvilCorp Affiliates / Qilin | Various Cybercrime | ClickFix and fake CAPTCHA lures trick users into pasting PowerShell in Windows Run dialog; present in 57.5% of 2026 intrusions | [Blackpoint Cyber - 2026 Annual Threat Report](https://blackpointcyber.com/resources/reports/2026-annual-threat-report/) |
| Any local attacker (CIFSwitch) | Any motivated local attacker | Python3-based LPE exploit (732 bytes); deterministic root escalation on vulnerable Linux distributions including AlmaLinux 9.7, Rocky Linux 9, CentOS Stream 9, SLES 15; CVE pending; PoC public May 28, 2026 | [BleepingComputer (2026-05-30)](https://www.bleepingcomputer.com/news/security/new-cifswitch-linux-flaw-gives-root-on-multiple-distributions/), [heyitsas.im — CIFSwitch](https://heyitsas.im/posts/cifswitch/) |
| Unknown (CVE-2026-20245 exploiters, June 2026) | Unknown / Possible UAT-8616 | Active exploitation of Cisco SD-WAN Manager CLI command injection zero-day (CVSS 7.8); requires netadmin credentials (chained from CVE-2026-20182 auth bypass or stolen creds); escalates to root via crafted file upload; allows configuration push to all managed edge devices; 7th SD-WAN zero-day exploited in 2026; no patch as of June 5, 2026 | [Cisco Advisory cisco-sa-sdwan-privesc-4uxFrdzx (2026-06-05)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx), [Help Net Security (2026-06-05)](https://www.helpnetsecurity.com/2026/06/05/cisco-sd-wan-cve-2026-20245-0-day-exploited/) |
