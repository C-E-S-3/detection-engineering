---
scraped_at: 2026-09-29T14:30:00Z
source_url: https://www.microsoft.com/en-us/security/blog/2026/09/29/phishing-abuses-rmm-tools-persistent-access/
report_type: threat-intel
severity: high
title: "Phishing Campaigns Abuse MSP360 RMM and ConnectWise ScreenConnect for Persistent Unauthorized Access"
---

# Phishing Campaigns Abuse MSP360 RMM and ConnectWise ScreenConnect for Persistent Unauthorized Access

## 1. IOCs

### Domains (Delivery Infrastructure)
| Indicator | Type | Context |
|-----------|------|---------|
| `adswre[.]cfd` | Delivery | Phishing lure landing page distributing trojanized MSP360 RMM installer |
| `trews[.]cfd` | Delivery | Phishing lure / ScreenConnect download redirect |
| `adsaw[.]cfd` | Delivery | Phishing lure landing page |
| `sdfghj[.]rd-team[.]ru` | Delivery | C2 / callback domain used by deployed RMM agents |
| `swedcorry[.]stefneyv[.]com` | Delivery | Phishing lure hosting subdomain |
| `ojsuyw[.]niyari[.]org` | Delivery | Phishing lure hosting subdomain |
| `bunstar[.]harej[.]si` | Delivery | Phishing lure hosting subdomain |

### File Hashes (SHA256 — MSP360 installer variants and ScreenConnect payloads)
| Hash | Context |
|------|---------|
| `108ef7e628d7a20bd6241a5b57149e27a6061f467123eb64061975559f8f73dc` | Trojanized MSP360 RMM v2.5.0.67 installer |
| `f094b8263471c7b76dbed03d420736449920368fa0eca2ed6b1aea2645138d97` | Trojanized MSP360 RMM installer variant |
| `857c2f283de799faa74b56e862c0a9f96e67aa1b4fa4a9e46395098365b99de3` | Trojanized MSP360 installer |
| `6a89de024ca62536de6f5fc10e49896bb1ac330ca39dce30203afdcc45ae237e` | ScreenConnect client installer (malicious configuration) |
| `4188c6588f3dcda881c3f2d12df580051179a999f040b799af506edeb3211a26` | ScreenConnect client installer variant |
| `ceb3f7fe9a618ff29a21b126383c23900fad58d6ae2b5552d7e306e4b6acf4b0` | MSP360 payload component |
| `02f2ce03a2650f17bfe6e8744eebbf58522016cbdb92af8f2217b5dd4a1ad550` | MSP360 payload component |
| `499d07894f730fb685ee3cbfc1a933e0da93750c1ed25a49b2eb9c32adef156a` | RMM installer |
| `d49cc01641c3045bf3119f9d71e7ffd29bfce32ca4b27cc96340716ed4d41cdc` | RMM installer |
| `67c979dc13961b09f24f85a801e4c918420adca6117c92efbeeeaa68a6344f55` | RMM installer |
| `6cc665057c4a4fe42a309afd3a7fa96cf1af126e9c6e08e56df5105e05378bcc` | RMM installer |
| `dd434f3ffcafeda538d43226665115ba136ad0fdb43dad8536e1368ca9a17b64` | RMM installer |
| `40f8e774e1e7a484b78c7ae4336bc47aa9cab20dc8e1e67d89838e807975f9b1` | RMM installer |
| `3ff5e49fd2f2bd0758467763c44d69e781b7460af84a6e3966e2621bc5bf7096` | RMM installer |
| `374c4934b14a1151ea68847c8627c3f1c0b878f4e673bda3f15e4388dfde0187` | RMM installer |
| `bc8b1b0c80512ba0e8ffccfee5b507df16a3355db1143c3ba81ef42dac1baa6c` | RMM installer |
| `c2c004a56de2a99f5b06ceb58d8a4b371fb60fd66ff5936786fe8d8037ead208` | RMM installer |
| `5bf8cf29ac6803e7269b045dea48003af7cfe48bedfc081b57ff9e86cb08971b` | RMM installer |
| `19035c8e2520fb70b3e2ec5338c14311b88a26cc1fb8304a01494260b6b55af1` | RMM installer |
| `d232d82e410de12702a67c58acf927304ee42f3e6d81a9d71eca99f9052126db` | RMM installer |
| `d3cb7ded277b49be06e6a1860f7c7e913e252802e9d32453a185e24797bf53ef` | RMM installer |
| `e31e5da7c58a7e8f89f9629f095edd7d741a1fb0b85fcb39f3818dbd9497b1e3` | RMM installer |
| `1a534d04bf30894d20764e91f7e94e0a73f060f0abacc9feeedba427995c83a8` | RMM installer |
| `77fb0e75f4396cb57bbbd28f6dc5310369a87abec9e2acc457aa99a0063ed27a` | RMM installer |
| `fc96a04c615847f0fb1391f04d9d1aac7f78ddfb7d459168df0a4172b98354e2` | RMM installer |
| `06ad69b9bebad3cc75b594cc5bb1ca0035ea22bb8a683002ca051d948566426b` | RMM installer |
| `a93c946c237b981189d2668d938a9d4d1d9681757e48dae8d9d65ed25b5da657` | RMM installer |
| `529543b4fe6a4c21d28be56dbf92fcac91d8df808d8518b4275c973fa547ad63` | RMM installer |
| `ccea4e1acc51ac43ba9da76ada00e7e308cc33d9c5c264dff82d1be83e957b88` | RMM installer |
| `a03c84ae9e569c04fdd271277f508bba5a299d53c3c0efe0819338d178fe1c5b` | RMM installer |

### File Hashes (SHA1)
| Hash | Type | Context |
|------|------|---------|
| `f34330d4c6e0aa978dc3af40360c14b31ad51127` | SHA1 | MSP360 RMM v2.5.0.67 trojanized installer; phishing distribution September 2026 |

---

## 2. TTPs

| Tactic | Technique ID | Technique | Usage |
|--------|-------------|-----------|-------|
| Initial Access | TA0001 | T1566.002 | Spearphishing Link — email with link to lure pages hosting trojanized RMM software downloads |
| Execution | TA0002 | T1204.002 | User Execution: Malicious File — victim runs downloaded RMM installer thinking it is legitimate IT tooling |
| Execution | TA0002 | T1218.007 | Signed Binary Proxy Execution: Msiexec — MSI-packaged installers distributed to bypass simple hash detection |
| Persistence | TA0003 | T1543.003 | Create or Modify System Process: Windows Service — MSP360/ScreenConnect installs as a persistent Windows service |
| Persistence | TA0003 | T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys — RMM client persistence via registry |
| Command and Control | TA0011 | T1219 | Remote Access Software — attacker uses MSP360 RMM and ScreenConnect as legitimate-appearing C2 |
| Execution | TA0002 | T1059.001 | PowerShell — post-access lateral commands delivered via RMM console |

---

## 3. Malware & Tools

**MSP360 RMM v2.5.0.67** (trojanized legitimate software)
- Attacker-controlled MSP360 deployment configured to phone home to attacker-controlled management console
- Installs as Windows service `MSP360RemoteDesktopService`; provides full desktop control, file transfer, and command execution
- Lure: fake IT helpdesk or software update notification emails

**ConnectWise ScreenConnect** (trojanized / attacker-configured legitimate software)
- ScreenConnect clients pre-configured to connect to attacker-hosted or cloud-hosted ScreenConnect server
- Appears as `ScreenConnect.ClientService` in services list; blends with legitimate MSP deployments

---

## 4. Threat Actor / Campaign Attribution

Unattributed cybercrime threat actor. Activity observed September 2026. The campaign targets small-to-medium business employees and individuals, using IT helpdesk and software update lure themes. The use of two separate legitimate RMM tools suggests an actor maintaining fallback access channels and familiarity with MSP tooling — consistent with threat actors targeting managed service providers or their customers.

---

## 5. Splunk Detection Searches

### Detect RMM Software Installed Outside Approved Paths
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name IN ("msp360rmm.exe","MSP360Backup.exe",
    "ScreenConnect.ClientService.exe","ScreenConnect.WindowsClient.exe")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process,"(?i)(temp|appdata|downloads|desktop|users)"), 90,
    NOT match(process,"(?i)program files"), 80,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

### Detect DNS Queries to Known RMM Phishing Delivery Domains
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Resolution.DNS
  where DNS.query IN ("adswre.cfd","trews.cfd","adsaw.cfd","sdfghj.rd-team.ru",
    "swedcorry.stefneyv.com","ojsuyw.niyari.org","bunstar.harej.si")
  by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=100
| table firstTime lastTime src query answer risk_score
```

### Detect RMM Service Created on Host Without Prior Approved Baseline
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Services
  where Services.service_name IN ("MSP360RemoteDesktopService","ScreenConnect Client*","ConnectWise*")
    AND Services.status="running"
  by Services.dest Services.user Services.service_name Services.service_path
| `drop_dm_object_name(Services)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(service_path,"(?i)(appdata|temp|downloads)"), 90,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime dest user service_name service_path risk_score
```

---

## 6. Executive Summary

Microsoft Threat Intelligence published analysis on September 29, 2026 documenting a phishing campaign that delivers trojanized versions of legitimate RMM software — specifically **MSP360 RMM v2.5.0.67** and **ConnectWise ScreenConnect** — to establish persistent unauthorized access to victim endpoints.

**Attack chain:** Victims receive spearphishing emails (or see malvertising) directing them to lure pages themed as IT support portals or software update notifications. The pages host installer packages for MSP360 RMM or ScreenConnect that are pre-configured to connect to attacker-controlled management consoles. Once the victim runs the installer, the RMM software installs as a legitimate-looking Windows service, providing the attacker with persistent full desktop access, file transfer, and command execution capability — all appearing as legitimate remote support traffic.

**Why this is significant:** Legitimate RMM software is whitelisted by most security tools, appears in many enterprise environments, and generates network traffic that is difficult to distinguish from authorized IT activity. The attacker effectively gains a persistent C2 channel that survives reboots, uses signed binaries, and blends with normal MSP operations.

**Detection challenges:** Hash-based IOC detection is immediately actionable for the 30+ identified installers. Behavioral detection must look for RMM software installed from non-standard paths (AppData, Temp, Downloads) or with unknown parent processes, and for RMM services appearing on hosts that have no managed IT relationship.

---

## References

- [Microsoft Security Blog — Phishing Abuses RMM Tools (2026-09-29)](https://www.microsoft.com/en-us/security/blog/2026/09/29/phishing-abuses-rmm-tools-persistent-access/)
- [MITRE ATT&CK T1219 — Remote Access Software](https://attack.mitre.org/techniques/T1219/)
- [CISA Advisory on Malicious Use of RMM Software (AA23-025A)](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a)
- [MSP360 RMM product page](https://www.msp360.com/rmm.aspx)
- [ConnectWise ScreenConnect security guidance](https://docs.connectwise.com/ConnectWise_ScreenConnect_Documentation)
