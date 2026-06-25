---
scraped_at: "2026-06-17T00:00:00Z"
source_url: "https://www.varonis.com/blog/ghosttree-ntfs-trick"
report_type: threat-intel
severity: high
title: "GhostTree: Varonis Discloses NTFS Junction Recursive Loop Technique That Causes EDR Scanners to Hang"
---

## 1. IOCs

No specific threat-actor IOCs. GhostTree is a **technique**, not a specific malware campaign. Detection relies on behavioral monitoring of NTFS junction creation patterns.

**Technique Artifact:**
- Directory containing an NTFS junction where the junction target points to an ancestor directory, creating a recursive loop
- Junction created without administrative privileges using: `mklink /J <path>\loop <path>` (where `<path>` is an ancestor of `<path>\loop`)
- Two standard Windows commands (or equivalent PowerShell `New-Item -ItemType Junction`) are sufficient to create the evasion structure

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique | ID | Usage |
|--------|-----------|-----|-------|
| Defense Evasion | Impair Defenses: Disable or Modify Tools | T1562.001 | Recursive NTFS junction loop causes EDR file system scanner to follow the infinite path and never complete scanning of the directory; malicious payload in the same parent directory goes unscanned |
| Defense Evasion | File System Permissions Weakness | T1222.001 | NTFS junction creation requires only standard write permissions on the directory — no administrative privileges required, making this accessible to any compromised low-privileged user |
| Defense Evasion | Indicator Removal | T1070 | Malicious files co-located alongside the junction in the parent directory remain undetected because AV/EDR scanner never exits the recursive traversal |

## 3. Malware & Tools

No specific malware family. The technique is two operating-system commands and can be incorporated into any malware, post-exploitation toolkit, or red team operation. The minimal footprint (no custom binary required, uses native `cmd.exe`/`mklink`) makes attribution difficult.

**Minimal exploitation:**
```
mkdir C:\path\to\trap
mklink /J C:\path\to\trap\loop C:\path\to\trap
```

Malicious payload (script, binary, etc.) placed in `C:\path\to\trap\` is co-located with the junction. When a scanner attempts to recursively walk `trap\`, it enters `loop\` → `trap\` → `loop\` → ... and never finishes, leaving the payload unscanned.

## 4. Threat Actor / Campaign Attribution

No specific threat actor confirmed to have used GhostTree in the wild at time of disclosure. Varonis Threat Labs disclosed the technique as a research finding on June 16, 2026, after observing it during threat research. The technique was validated against Windows Defender and multiple EDR products.

**Vendor response timeline:**
- Varonis reported to Microsoft Security Response Center
- Microsoft initially closed the ticket: "bypassing Defender is not crossing a security boundary"
- Microsoft subsequently deployed a patch addressing the underlying recursive scanner vulnerability

No CVE has been publicly assigned. Check Windows security update history for patches addressing NTFS junction scanner loop behavior (expected in a Patch Tuesday update following June 2026).

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.process_name="cmd.exe" OR Processes.process_name="powershell.exe")
    AND (Processes.process="*mklink*" AND Processes.process="*/J*")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process, "(?i)(temp|tmp|appdata|public|programdata)"), 85,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name="powershell.exe"
    AND Processes.process="*New-Item*" AND Processes.process="*Junction*"
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process, "(?i)(temp|tmp|appdata|public|programdata)"), 85,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
index=wineventlog EventCode=4656 OR EventCode=4663
  ObjectType="File"
| eval is_junction_op=if(match(ObjectName, "(?i)junction|link"), 1, 0)
| search AccessMask="0x40" OR AccessMask="0x80"
| stats count min(_time) as firstTime max(_time) as lastTime by SubjectUserName Computer ObjectName
| rename SubjectUserName as user, Computer as dest
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=60
| table firstTime lastTime dest user ObjectName risk_score
```

```spl
`sysmon` EventCode=11 TargetFilename="*"
| eval fname_lower=lower(TargetFilename)
| search (Image="*cmd.exe" OR Image="*powershell.exe")
  AND (CommandLine="*mklink*" AND CommandLine="*/J*")
| stats count min(_time) as firstTime max(_time) as lastTime by Computer User Image CommandLine TargetFilename
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=if(match(TargetFilename, "(?i)(temp|tmp|appdata|public|programdata)"), 85, 65)
| table firstTime lastTime Computer User Image CommandLine TargetFilename risk_score
```

## 6. Executive Summary

On June 16, 2026, Varonis Threat Labs disclosed **GhostTree**, a technique that exploits Windows NTFS directory junctions to create recursive directory loops that permanently stall EDR and antivirus file system scanners.

The technique is deceptively simple: by using the built-in `mklink /J` command (or PowerShell `New-Item -ItemType Junction`), an attacker with only standard write permissions creates a junction that points back to an ancestor directory, forming an infinite loop. When any security scanner attempts to recursively enumerate the directory to find malicious files, it follows the loop endlessly, consuming CPU/memory and never completing the scan. Malware placed in the same parent directory as the junction goes completely undetected.

The technique was validated against **Windows Defender** and multiple commercial EDR products. No administrative privileges are required. Varonis reported the issue to Microsoft; Microsoft initially declined to classify it as a security boundary violation, but subsequently patched the underlying recursive scanning behavior.

**Why this matters:** Any ransomware operator, infostealer, or post-exploitation toolkit can incorporate two OS commands to drop malicious payloads in a junction-protected directory and guarantee they won't be scanned by most Windows security products. The technique is especially effective when combined with process injection into a legitimate host process (as in the DragonForce Backdoor.Turn campaign).

**Detection focus:**
- Monitor for `cmd.exe`/`powershell.exe` creating NTFS junctions (`mklink /J`) in user-writable directories (TEMP, AppData, Public, ProgramData)
- Sysmon Event ID 15 (File Stream Creation) or custom Sysmon configuration for junction creation detection
- Alert on `New-Item -ItemType Junction` in PowerShell command lines
- Audit directory structures in temp/staging directories for junctions pointing to ancestors

## References

- [Varonis Threat Labs — GhostTree: Unveiling Path Manipulation Techniques (2026-06-16)](https://www.varonis.com/blog/ghosttree-ntfs-trick)
- [BleepingComputer — GhostTree Attack Abused Recursive Windows Junctions (2026-06-16)](https://www.bleepingcomputer.com/news/security/ghosttree-attack-abused-recursive-windows-junctions-to-hide-malware/)
- [CyberSecurityNews — GhostTree Attack EDR Products (2026-06-16)](https://cybersecuritynews.com/ghosttree-attack-edr-products/)
- [MITRE ATT&CK — T1562.001: Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)
- [MITRE ATT&CK — T1222.001: File System Permissions Weakness](https://attack.mitre.org/techniques/T1222/001/)
