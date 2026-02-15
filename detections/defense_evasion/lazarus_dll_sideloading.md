# Lazarus DLL Sideloading

## Description

Detects potential DLL sideloading by identifying DLL execution from non-standard paths (outside System32, SysWOW64, Program Files) that appear on fewer than 5 hosts in the environment. DLL sideloading is a key Lazarus Group technique where legitimate applications are used to load malicious DLLs from attacker-controlled directories.

False positive sources: Uncommon legitimate software installed in non-standard paths. Tuning: adjust the affected_hosts threshold and add known-good DLL paths.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Defense Evasion |
| Tactic ID | TA0005 |
| Technique | Hijack Execution Flow: DLL Side-Loading |
| Technique ID | T1574.002 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Installation |

## Splunk Detection Query

```spl
`crowdstrike`
process_name IN ("*.dll")
| search NOT (process_path="C:\\Windows\\System32\\*" OR process_path="C:\\Windows\\SysWOW64\\*"
              OR process_path="C:\\Program Files\\*" OR process_path="C:\\Program Files (x86)\\*")
| stats count dc(src) as affected_hosts by process_name, process_path, parent_process_name
| where affected_hosts < 5
| sort - count
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| DLL from non-standard path on < 5 hosts | Medium-High | Low prevalence DLLs in unusual paths are strong sideloading indicators |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Lazarus Group (HIDDEN COBRA) | [MITRE - Lazarus Group (G0032)](https://attack.mitre.org/groups/G0032/) |

## References

- [MITRE ATT&CK - DLL Side-Loading (T1574.002)](https://attack.mitre.org/techniques/T1574/002/)
- [AhnLab - Lazarus DLL Side-Loading Analysis](https://asec.ahnlab.com/en/57873/)
