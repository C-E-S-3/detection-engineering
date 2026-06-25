# FishMonger SprySOCKS Print Processor Persistence

## Description

Detects registration of a malicious Windows Print Processor DLL — the primary persistence mechanism used by SprySOCKS WIN_PLUS, a Windows backdoor deployed by FishMonger (Earth Lusca / Aquatic Panda), a China-nexus APT operated by the I-SOON contractor group.

WIN_PLUS registers a malicious DLL as a custom Print Processor named `VSPMsg` under `HKLM\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Print Processors\VSPMsg`. The Windows Print Spooler service (`spoolsv.exe`) loads this DLL at startup, injecting the backdoor into `svchost.exe` via doppelgänging-like techniques.

Print Processor key modifications are rare in normal environments. Legitimate installs occur during printer driver deployments and some enterprise print management solutions (e.g., PaperCut, UniFlow). Any unexpected `Driver` value written under the Print Processors registry path warrants immediate investigation. Both 32-bit and 64-bit environments (`Windows x64`, `Windows NT x86`) should be monitored.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Persistence |
| Tactic ID | TA0003 |
| Technique | Boot or Logon Autostart Execution: Print Processors |
| Technique ID | T1547.012 |
| Secondary Tactic | Defense Evasion (TA0005) — loaded via trusted Spooler service |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Installation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Registry
where Registry.registry_path="*\\Control\\Print\\Environments\\*\\Print Processors\\*"
  AND Registry.registry_value_name="Driver"
  AND Registry.action=modified
by Registry.dest Registry.user Registry.registry_path Registry.registry_value_name Registry.registry_value_data
| `drop_dm_object_name(Registry)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    like(registry_value_data, "%.dat"), 95,
    like(registry_value_data, "%temp%"), 90,
    like(registry_value_data, "%appdata%"), 90,
    like(registry_value_data, "%programdata%"), 85,
    1=1, 80)
| where risk_score >= 75
| table firstTime lastTime dest user registry_path registry_value_name registry_value_data risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| DLL path ends in `.dat` extension | 95 | SprySOCKS WIN_PLUS stores payload as `.dat` file in spool directories to masquerade as data files |
| DLL path includes `%temp%` | 90 | Print Processor DLLs should never reside in temp directories |
| DLL path includes `%appdata%` | 90 | Print Processor DLLs should never reside in user-writable AppData paths |
| DLL path includes `%programdata%` | 85 | ProgramData-based Print Processor is suspicious but could be from legitimate print software |
| Any other unexpected `Driver` write | 80 | All modifications to Print Processor keys in non-print-server environments are high confidence suspicious |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| FishMonger / Earth Lusca (TAG-22, Aquatic Panda, Red Dev 10) | [MITRE ATT&CK G0010](https://attack.mitre.org/groups/G0010/), [ESET Research 2026-06-16](https://www.welivesecurity.com/en/eset-research/fishmongers-arsenal-upgraded-sprysocks-windows/) |
| I-SOON (Anxun Information Technology) | [I-SOON Leak Analysis](https://github.com/mttaggart/opsec-by-the-numbers) |

## References

- [ESET — FishMonger's arsenal upgraded: SprySOCKS for Windows (2026-06-16)](https://www.welivesecurity.com/en/eset-research/fishmongers-arsenal-upgraded-sprysocks-windows/)
- [MITRE ATT&CK — T1547.012 Boot or Logon Autostart Execution: Print Processors](https://attack.mitre.org/techniques/T1547/012/)
- [MITRE ATT&CK — FishMonger / Earth Lusca Group (G0010)](https://attack.mitre.org/groups/G0010/)
- [The Hacker News — China-Linked SprySOCKS Backdoor Expands to Windows (2026-06-16)](https://thehackernews.com/2026/06/china-linked-sprysocks-backdoor-expands.html)
