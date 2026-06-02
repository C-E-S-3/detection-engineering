---
scraped_at: 2026-06-02T00:00:00Z
source_url: https://www.bleepingcomputer.com/news/security/windows-bitlocker-zero-day-gives-access-to-protected-drives-poc-released/
report_type: threat-intel
severity: high
title: "YellowKey & GreenPlasma: New Windows Zero-Days Enable BitLocker Bypass and CTFMON Privilege Escalation (Nightmare Eclipse Series)"
---

## 1. IOCs

No network indicators (domains, IPs, file hashes) have been published for YellowKey or GreenPlasma. Both are physical-access or local exploitation techniques — no C2 infrastructure is involved.

**Behavioral IOCs:**
- Execution of `reagentc.exe /boottore` scheduling an unplanned WinRE boot
- Execution of `reagentc.exe /setreimage` pointing to a non-standard WinRE image path
- Presence of crafted FsTx files on USB devices or the EFI System Partition
- Unexpected WinRE entry (Event ID 4001 "Windows Recovery Environment started") without an administrator-initiated action
- CTRL-triggered interactive shell (`cmd.exe`) spawned from `winre.exe` or `wpeutil.exe` context

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Defense Evasion | T1006 | Direct Volume Access | YellowKey: WinRE recovery session accesses the BitLocker-protected NTFS volume directly, bypassing OS-level encryption enforcement |
| Defense Evasion | T1553 | Subvert Trust Controls | YellowKey: crafted FsTx files placed on USB or EFI partition trigger unrestricted WinRE shell, neutralizing BitLocker's pre-boot authentication chain |
| Defense Evasion | T1200 | Hardware Additions | YellowKey: brief physical access with a specially prepared USB drive is sufficient to trigger the exploit chain |
| Privilege Escalation | T1068 | Exploitation for Privilege Escalation | GreenPlasma: low-privileged local user creates arbitrary memory-section objects in SYSTEM-writable object directory namespaces via CTFMON, enabling manipulation of privileged services |
| Initial Access | T1200 | Hardware Additions | YellowKey attack chain begins with connecting a prepared USB drive to the target system |

**YellowKey Attack Chain:**
1. Attacker creates a USB drive or modifies the EFI System Partition containing crafted FsTx files.
2. Attacker connects the USB to the target Windows 11 or Windows Server 2025 system with BitLocker enabled.
3. System is rebooted into Windows Recovery Environment (WinRE).
4. During the pre-boot recovery sequence, the attacker holds the CTRL key, triggering an unrestricted CMD shell via WinRE's emergency access mechanism.
5. The attacker gains read/write access to the BitLocker-protected volume from within the recovery environment without entering the BitLocker PIN or recovery key.

**GreenPlasma Attack Chain:**
1. Low-privileged local user runs the GreenPlasma PoC binary.
2. The exploit abuses Windows Collaborative Translation Framework (CTFMON) — specifically the ALPC port exposed by the framework — to create arbitrary memory-section objects within `\BaseNamedObjects\` or other object directories writable by SYSTEM.
3. Privileged services or drivers that trust these locations may be manipulated, leading to privilege escalation.
4. Note: the published PoC is incomplete and does not deliver a full SYSTEM shell; active exploitation has not been confirmed.

## 3. Malware & Tools

| Tool | Description |
|------|-------------|
| YellowKey PoC | Public proof-of-concept released June 1, 2026 on GitHub by Nightmare Eclipse; uses crafted FsTx filesystem objects to unlock WinRE shell and bypass BitLocker |
| GreenPlasma PoC | Partial proof-of-concept released June 1, 2026; targets CTFMON ALPC for arbitrary object-directory section creation; does not yet deliver SYSTEM shell |

## 4. Threat Actor / Campaign Attribution

| Attribute | Detail |
|-----------|--------|
| Researcher | Nightmare Eclipse (also known as Chaotic Eclipse on GitHub) |
| Motivation | Researcher expresses public dissatisfaction with Microsoft Security Response Center (MSRC) handling of vulnerability disclosures; releasing zero-days as leverage |
| Series | YellowKey/GreenPlasma are the fifth and sixth zero-days released by Nightmare Eclipse in a ~6-week campaign (preceding entries: BlueHammer CVE-2026-33825, RedSun CVE-2026-41091, UnDefend CVE-2026-45498, MiniPlasma cldflt.sys LPE) |
| Threat status | No confirmed exploitation by malicious threat actors as of June 2, 2026 for YellowKey or GreenPlasma; MiniPlasma and BlueHammer PoCs have been observed in pre-ransomware attack chains (see related detection files) |

## 5. Splunk Detection Searches

```spl
| comment "Search 1: YellowKey — reagentc.exe scheduling WinRE boot or modifying WinRE image path"
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
    match(process, "(?i)/setreimage"), 80,
    match(process, "(?i)/enable"), 50,
    1=1, 40)
| where risk_score >= 50
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score
```

```spl
| comment "Search 2: YellowKey — BitLocker suspension or unusual WinRE registry config modification"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Registry
  where Registry.registry_path IN (
      "*\\Control\\MiniNT*",
      "*\\Setup\\WinRE\\*",
      "*\\Recovery\\RecoveryEnvironment\\*",
      "*\\Policies\\Microsoft\\FVE\\*")
    AND Registry.action IN ("created","modified")
    AND NOT Registry.process_name IN ("reagentc.exe","MpSigStub.exe","svchost.exe","TiWorker.exe","TrustedInstaller.exe")
  by Registry.dest Registry.user Registry.registry_path
     Registry.registry_value_name Registry.process_name
| `drop_dm_object_name(Registry)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=75
| table firstTime lastTime dest user registry_path registry_value_name process_name risk_score
```

```spl
| comment "Search 3: GreenPlasma — CTFMON child process anomaly (spawning unexpected shell)"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name="ctfmon.exe"
    AND Processes.process_name IN ("cmd.exe","powershell.exe","powershell_ise.exe","wscript.exe","cscript.exe")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=80
| where risk_score >= 80
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score
```

**Tuning notes:**
- Search 1: `/boottore` is rarely legitimate outside of IT admin tasks — high fidelity. `/enable` will fire for any admin enabling WinRE during imaging or troubleshooting; correlate with change management records.
- Search 2: FVE registry modifications could occur during legitimate BitLocker configuration by GPO or endpoint management tools; tune with a whitelist of authorized management processes.
- Search 3: `ctfmon.exe` spawning a shell is highly anomalous; near-zero false positive rate in production environments.

## 6. Executive Summary

On June 1, 2026, the security researcher known as Nightmare Eclipse publicly released proof-of-concept code for two new Windows zero-day vulnerabilities: **YellowKey** (CVE-2026-45585) and **GreenPlasma** (no CVE assigned yet). These are the fifth and sixth zero-days released by this researcher in a ~6-week public disclosure campaign protesting Microsoft's handling of vulnerability reports.

**YellowKey (CVE-2026-45585, CVSS 6.8)** is a Windows security feature bypass that allows an attacker with brief physical access to sidestep BitLocker full-disk encryption on Windows 11 (24H2, 25H2, 26H1) and Windows Server 2025. The bypass exploits the Windows Recovery Environment (WinRE): by placing crafted FsTx files on a USB drive or the EFI System Partition and rebooting into WinRE, the attacker can trigger an unrestricted command prompt via the CTRL key — gaining direct access to the BitLocker-protected volume without the PIN or recovery key. Microsoft has acknowledged the issue and recommends switching BitLocker protectors from TPM-only to TPM+PIN as an immediate mitigation.

**GreenPlasma** (no CVE) is a local privilege escalation targeting Windows Collaborative Translation Framework (CTFMON). The PoC is incomplete — it demonstrates object-directory manipulation via CTFMON's ALPC interface but does not yet achieve a full SYSTEM shell. No active exploitation has been confirmed. Microsoft is investigating.

These disclosures come alongside the YellowKey/GreenPlasma researcher's earlier MiniPlasma (cldflt.sys LPE, already in our detection repo), BlueHammer (CVE-2026-33825, Defender SAM-copy TOCTOU), RedSun (CVE-2026-41091), and UnDefend (CVE-2026-45498) — the latter three of which have been observed in pre-ransomware attack chains and are in the CISA KEV catalog. Organizations should treat the entire Nightmare Eclipse series as an elevated risk surface.

**Immediate actions:**
1. Switch BitLocker protectors from TPM-only to **TPM+PIN** on all managed Windows 11 and Server 2025 systems to mitigate YellowKey.
2. Deploy Search 1 to detect anomalous `reagentc.exe /boottore` or `/setreimage` invocations.
3. Enforce physical access controls (locked chassis, disabled USB boot in BIOS/UEFI with BIOS password) to raise the bar for physical-access attacks.
4. Monitor for Search 3 (ctfmon.exe spawning shells) to catch opportunistic GreenPlasma exploitation.
5. Track Microsoft June 10, 2026 Patch Tuesday for patches addressing these zero-days.

## References

- [BleepingComputer — Windows BitLocker zero-day gives access to protected drives, PoC released (2026-06-01)](https://www.bleepingcomputer.com/news/security/windows-bitlocker-zero-day-gives-access-to-protected-drives-poc-released/)
- [SecurityWeek — Researcher Drops YellowKey, GreenPlasma Windows Zero-Days (2026-06-01)](https://www.securityweek.com/researcher-drops-yellowkey-greenplasma-windows-zero-days/)
- [SOC Prime — CVE-2026-45585: YellowKey BitLocker Bypass](https://socprime.com/blog/cve-2026-45585-yellowkey-bitlocker-bypass/)
- [The Hacker News — Windows Zero-Days Expose BitLocker Bypasses and CTFMON Privilege Escalation (2026-05-31)](https://thehackernews.com/2026/05/windows-zero-days-expose-bitlocker.html)
- [Hive Security — YellowKey: The BitLocker Bypass Hidden in Windows Recovery](https://hivesecurity.gitlab.io/blog/yellowkey-bitlocker-bypass-winre-windows-11/)
- [Barracuda Blog — Nightmare Eclipse: six zero-days, six weeks and one big grudge (2026-05-19)](https://blog.barracuda.com/2026/05/19/nightmare-eclipse-zero-days-grudge)
- [MITRE ATT&CK — T1006 Direct Volume Access](https://attack.mitre.org/techniques/T1006/)
- [MITRE ATT&CK — T1553 Subvert Trust Controls](https://attack.mitre.org/techniques/T1553/)
- [MITRE ATT&CK — T1068 Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)
- [CVE-2026-45585 — Windows BitLocker Security Feature Bypass](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45585)
