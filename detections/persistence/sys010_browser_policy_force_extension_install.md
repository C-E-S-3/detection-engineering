# SYS010 Browser Management Policy Force-Extension Installation

## Description

Detects adversaries abusing enterprise browser management registry policies to silently force-install malicious browser extensions outside the browser extension store review process. The SYS010 infostealer (Bitdefender Labs, November 2026) achieves this by executing a PHP component (`eclient.php`) that writes Chrome Enterprise Group Policy keys — including `ExtensionInstallForcelist` and `CloudManagementEnrollmentToken` — to the Windows registry, enrolling the browser into an attacker-controlled Google Workspace Admin console and deploying a malicious extension. For Firefox, the equivalent mechanism writes to `HKLM\SOFTWARE\Policies\Mozilla\Firefox\Extensions\Install` and disables Developer Tools.

Extensions installed via enterprise policy bypass Chrome Web Store vetting, do not trigger the standard "new extension installed" browser alert, persist across browser restarts, and can survive extension management page removal attempts. The SYS010 Chrome extension ("Docs Helper 1.0.25", ID `ikpkhjechdnnfjedponpfmigmgcjgabi`) harvests Gmail/Outlook messages, steals session cookies across all sites, and exfiltrates Meta Business account data to C2 servers (lelebag[.]com, esora[.]top), polling every 5 minutes with C2 endpoints updated via Telegram and Cloudflare R2.

False positives: Legitimate IT department deployment of approved Chrome extensions via Group Policy or Intune/MDM would write to the same registry paths. Analyst should verify: (1) the extension ID in `ExtensionInstallForcelist` appears in the organization's approved extension policy, (2) the `CloudManagementEnrollmentToken` matches the organization's Google Workspace tenant, and (3) the process writing the keys is `msiexec.exe`, `gpupdate.exe`, or a recognized MDM agent rather than a user-space process.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Persistence |
| Tactic ID | TA0003 |
| Technique | Browser Extensions |
| Technique ID | T1176 |
| Secondary Tactic | Defense Evasion |
| Secondary Tactic ID | TA0005 |
| Secondary Technique | Modify Registry |
| Secondary Technique ID | T1112 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Installation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Registry
  where (Registry.registry_path="*\\SOFTWARE\\Policies\\Google\\Chrome\\ExtensionInstallForcelist*"
      OR Registry.registry_path="*\\SOFTWARE\\Policies\\Google\\Chrome\\CloudManagementEnrollmentToken*"
      OR Registry.registry_path="*\\SOFTWARE\\Policies\\Google\\Chrome\\ExtensionSettings*"
      OR Registry.registry_path="*\\SOFTWARE\\Policies\\Mozilla\\Firefox\\Extensions\\Install*"
      OR Registry.registry_path="*\\SOFTWARE\\Policies\\Mozilla\\Firefox\\Extensions\\Locked*")
  by Registry.dest Registry.user Registry.registry_path Registry.registry_value_data
     Registry.process_guid Registry.process_name
| `drop_dm_object_name(Registry)`
| eval mdm_expected_writers=mvappend("msiexec.exe","gpupdate.exe","lsass.exe","services.exe","svchost.exe")
| eval risk_score=case(
    NOT match(process_name, "(?i)(msiexec\.exe|gpupdate\.exe|lsass\.exe|services\.exe|svchost\.exe)"), 90,
    1=1, 50)
| where risk_score >= 50
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user process_name registry_path registry_value_data risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Resolution.DNS
  where DNS.query IN ("lelebag.com", "esora.top")
  by DNS.src DNS.query
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95, threat="SYS010 Browser Extension C2"
| table firstTime lastTime src query threat risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Browser policy registry key written by non-MDM/GPO process (e.g., PHP, cmd.exe, PowerShell) | 90 | Unexpected process writing enterprise browser policy is high-confidence malicious |
| Browser policy registry key written by recognized MDM/GPO process (msiexec, gpupdate, etc.) | 50 | Possibly legitimate; warrants verification against approved extension policy |
| DNS query to known SYS010 C2 domain (lelebag.com, esora.top) | 95 | Direct IOC match to Bitdefender-confirmed C2 infrastructure |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| SYS010 Operator (Unknown Financially Motivated Actor) | [Bitdefender Labs SYS010 Reloaded](https://www.bitdefender.com/en-us/blog/labs/sys010-reloaded-malvertising-campaign-targeting-meta-business-accounts) |
| SYS01 Infostealer Operator (Predecessor Campaign) | [MITRE ATT&CK T1176 — Browser Extensions](https://attack.mitre.org/techniques/T1176/) |

## References

- [Bitdefender Labs — SYS010 Reloaded: Malvertising Campaign Targeting Meta Business Accounts (Nov 26, 2026)](https://www.bitdefender.com/en-us/blog/labs/sys010-reloaded-malvertising-campaign-targeting-meta-business-accounts)
- [MITRE ATT&CK T1176 — Browser Extensions](https://attack.mitre.org/techniques/T1176/)
- [MITRE ATT&CK T1112 — Modify Registry](https://attack.mitre.org/techniques/T1112/)
- [Google Chrome Enterprise — ExtensionInstallForcelist Policy](https://chromeenterprise.google/policies/#ExtensionInstallForcelist)
- [Mozilla Firefox — Extensions Install Policy](https://mozilla.github.io/policy-templates/#extensions)
