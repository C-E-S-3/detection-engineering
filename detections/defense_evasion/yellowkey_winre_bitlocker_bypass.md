# YellowKey — Windows Recovery Environment BitLocker Bypass

## Description

Detects abuse of the Windows Recovery Environment (WinRE) to bypass BitLocker full-disk encryption, as described in the YellowKey zero-day (CVE-2026-45585) disclosed by researcher Nightmare Eclipse on June 1, 2026. The attack requires brief physical access: an attacker places crafted FsTx files on a USB drive or the EFI System Partition, reboots the target Windows 11 or Windows Server 2025 system into WinRE, and uses the CTRL key to trigger an unrestricted command prompt that can access the BitLocker-protected NTFS volume without entering the PIN or recovery key.

Detection focuses on three observable signals: (1) `reagentc.exe` invoked with flags that schedule WinRE boot (`/boottore`) or redirect the WinRE image path (`/setreimage`); (2) anomalous modifications to WinRE-related registry keys or BitLocker Group Policy (FVE) keys by non-administrative processes; (3) the WinRE CTRL-shell pattern — a shell spawned from WinRE/WinPE host processes.

False positives: IT administrators use `reagentc.exe /enable` when re-imaging systems and when running BCD repair tools; `/boottore` is used by Windows Update in rare firmware-update scenarios. Correlate with change management records. `reagentc.exe /setreimage` with non-standard paths is unusual outside of enterprise WinRE customization projects.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Defense Evasion |
| Tactic ID | TA0005 |
| Technique | Direct Volume Access |
| Technique ID | T1006 |

Secondary: T1553 (Subvert Trust Controls) — bypassing BitLocker pre-boot authentication; T1200 (Hardware Additions) — physical USB device introduction.

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Actions on Objectives |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name="reagentc.exe"
    AND (Processes.process="*/boottore*"
         OR Processes.process="*/setreimage*"
         OR Processes.process="*/enable*")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process, "(?i)/boottore"), 85,
    match(process, "(?i)/setreimage") AND NOT match(process, "(?i)\\\\Windows\\\\"), 80,
    match(process, "(?i)/enable") AND NOT user IN ("SYSTEM","NT AUTHORITY\\SYSTEM"), 55,
    1=1, 30)
| where risk_score >= 55
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score
```

**Supplemental — WinRE/FVE registry modification by non-administrative processes:**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Registry
  where (Registry.registry_path="*\\Control\\MiniNT*"
         OR Registry.registry_path="*\\Setup\\WinRE\\*"
         OR Registry.registry_path="*\\Recovery\\RecoveryEnvironment\\*"
         OR Registry.registry_path="*\\Policies\\Microsoft\\FVE\\*")
    AND Registry.action IN ("created","modified")
    AND NOT Registry.process_name IN (
        "reagentc.exe","TrustedInstaller.exe","TiWorker.exe",
        "MpSigStub.exe","svchost.exe","System")
  by Registry.dest Registry.user Registry.registry_path
     Registry.registry_value_name Registry.registry_value_data Registry.process_name
| `drop_dm_object_name(Registry)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=75
| where risk_score >= 75
| table firstTime lastTime dest user registry_path registry_value_name registry_value_data process_name risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| `reagentc.exe /boottore` | 85 | Scheduling WinRE boot on next restart has very narrow legitimate use; strong indicator of attack preparation |
| `reagentc.exe /setreimage` with non-Windows path | 80 | Redirecting WinRE to a custom image path from a non-standard location strongly suggests a trojanized WinRE being staged |
| `reagentc.exe /enable` by non-SYSTEM process | 55 | Enabling WinRE by non-privileged accounts is unusual; could be a setup step preceding BitLocker bypass |
| WinRE/FVE registry key modified by unexpected process | 75 | These registry paths control WinRE boot behavior and BitLocker policy; unauthorized modification is high-risk |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Nightmare Eclipse (security researcher — PoC only; no confirmed malicious-actor exploitation as of June 2026) | [BleepingComputer — YellowKey PoC (2026-06-01)](https://www.bleepingcomputer.com/news/security/windows-bitlocker-zero-day-gives-access-to-protected-drives-poc-released/) |

## References

- [BleepingComputer — Windows BitLocker zero-day gives access to protected drives, PoC released (2026-06-01)](https://www.bleepingcomputer.com/news/security/windows-bitlocker-zero-day-gives-access-to-protected-drives-poc-released/)
- [SecurityWeek — Researcher Drops YellowKey, GreenPlasma Windows Zero-Days (2026-06-01)](https://www.securityweek.com/researcher-drops-yellowkey-greenplasma-windows-zero-days/)
- [SOC Prime — CVE-2026-45585: YellowKey BitLocker Bypass](https://socprime.com/blog/cve-2026-45585-yellowkey-bitlocker-bypass/)
- [Hive Security — YellowKey: The BitLocker Bypass Hidden in Windows Recovery](https://hivesecurity.gitlab.io/blog/yellowkey-bitlocker-bypass-winre-windows-11/)
- [CVE-2026-45585 — Microsoft Security Response Center](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45585)
- [MITRE ATT&CK — T1006 Direct Volume Access](https://attack.mitre.org/techniques/T1006/)
- [MITRE ATT&CK — T1553 Subvert Trust Controls](https://attack.mitre.org/techniques/T1553/)
