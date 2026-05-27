# MuddyWater Signed Security-Software Binary DLL Sideloading

## Description

Detects Seedworm (MuddyWater) DLL sideloading via legitimately signed security and audio software binaries. In their Q1 2026 global espionage campaign, Seedworm placed malicious DLLs (`fmapp.dll`, `sentinelagentcore.dll`) in the same working directory as legitimate signed executables (`fmapp.exe` from Fortemedia, `sentinelmemoryscanner.exe` from SentinelOne). When the signed binary launches, Windows DLL search-order resolution loads the malicious DLL instead of the vendor's legitimate one.

Both malicious DLLs embed **ChromElevator**, an open-source tool that bypasses Chromium App-Bound Encryption (ABE, introduced Chrome v127+) to steal passwords, cookies, and payment card data. The DLL also beacons to attacker-controlled IP `157.20.182[.]49` for C2 tasking and uses the public file-sharing service `sendit.sh` for exfiltration.

The use of a security vendor's (SentinelOne's) signed binary as a sideloading carrier is a deliberate choice to exploit implicit trust in well-known security tools.

Detection signals:
- `fmapp.exe` or `sentinelmemoryscanner.exe` executing from a path other than their legitimate installation directories
- Either binary spawning unexpected child processes (cmd.exe, powershell.exe, etc.)
- Outbound connections from either process to non-vendor IPs

False positives: Legitimate Fortemedia audio driver installation/operation (`fmapp.exe` in `C:\Program Files\Fortemedia\` or similar); legitimate SentinelOne scanner operations (`sentinelmemoryscanner.exe` in `C:\Program Files\SentinelOne\`). Tune by excluding those expected paths.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Defense Evasion |
| Tactic ID | TA0005 |
| Technique | Hijack Execution Flow: DLL Side-Loading |
| Technique ID | T1574.002 |

Secondary techniques: T1555.003 (Credentials from Web Browsers — ChromElevator), T1567.002 (Exfiltration to Code Repository — sendit.sh).

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Installation |
| Actions on Objectives |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name IN ("fmapp.exe","sentinelmemoryscanner.exe")
  by Processes.dest Processes.user Processes.process_name Processes.process_path
     Processes.parent_process_name Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval is_legitimate=case(
    process_name="fmapp.exe" AND match(process_path,"(?i)\\\\Fortemedia\\\\"), "yes",
    process_name="sentinelmemoryscanner.exe" AND match(process_path,"(?i)\\\\SentinelOne\\\\"), "yes",
    1=1, "no")
| where is_legitimate="no"
| eval risk_score=case(
    process_name="sentinelmemoryscanner.exe", 90,
    process_name="fmapp.exe", 85,
    1=1, 80)
| table firstTime lastTime dest user process_name process_path parent_process_name risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN ("fmapp.exe","sentinelmemoryscanner.exe")
    Processes.process_name IN ("cmd.exe","powershell.exe","mshta.exe","wscript.exe",
                               "cscript.exe","rundll32.exe","regsvr32.exe","net.exe",
                               "whoami.exe","ipconfig.exe","nltest.exe","schtasks.exe")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    parent_process_name="sentinelmemoryscanner.exe", 95,
    parent_process_name="fmapp.exe", 90,
    1=1, 85)
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_ip="157.20.182.49"
  by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.action
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src_ip dest_ip dest_port action risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| `sentinelmemoryscanner.exe` executing from outside SentinelOne installation directory | 90 | SentinelOne scanner should only run from its install path; execution from temp/user dirs is DLL sideloading |
| `fmapp.exe` executing from outside Fortemedia installation directory | 85 | Fortemedia audio utility running from non-standard path indicates sideloading staging |
| Either binary spawning `cmd.exe`, `powershell.exe`, or recon utilities as child | 90–95 | These binaries have no legitimate reason to spawn shell utilities; indicates loaded malicious DLL executing |
| Outbound connection to 157.20.182.49 | 95 | Confirmed Seedworm C2 IP; direct IOC hit |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Seedworm / MuddyWater (MOIS, G0069) | [Symantec — Seedworm Q1 2026 Campaign](https://www.security.com/threat-intelligence/iran-seedworm-electronics), [MITRE ATT&CK G0069](https://attack.mitre.org/groups/G0069/) |

## References

- [Symantec / security.com — Seedworm Q1 2026 DLL Sideloading Campaign](https://www.security.com/threat-intelligence/iran-seedworm-electronics)
- [BleepingComputer — Iranian Hackers Targeted Major South Korean Electronics Maker](https://www.bleepingcomputer.com/news/security/iranian-hackers-targeted-major-south-korean-electronics-maker/)
- [MITRE ATT&CK G0069 — Seedworm/MuddyWater](https://attack.mitre.org/groups/G0069/)
- [MITRE ATT&CK T1574.002 — DLL Side-Loading](https://attack.mitre.org/techniques/T1574/002/)
- [MITRE ATT&CK T1555.003 — Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003/)
