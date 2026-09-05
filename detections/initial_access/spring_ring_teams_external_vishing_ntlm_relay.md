# Spring Ring: Microsoft Teams External Tenant Vishing and NTLM Relay via PetitPotam

## Description

Detects the Spring Ring campaign TTP chain: RMM tool execution following Microsoft Teams activity, combined with outbound SMB or NTLM relay indicators consistent with PetitPotam forced authentication. Attackers impersonate IT helpdesk personnel via external Microsoft Teams tenants, convince victims to install RMM software, then use `EfsRpcOpenFileRaw` (MS-EFSRPC) to coerce NTLM authentication from the victim machine to an attacker-controlled relay server, which is forwarded to an Active Directory Certificate Services endpoint to obtain a machine certificate.

False positives for the RMM query include legitimate IT support tools installed by the helpdesk. Correlate with Teams external tenant contact events in Azure AD / Entra audit logs to increase confidence. The outbound SMB query may fire for legitimate cross-subnet SMB traffic — scope with known-good destination IP ranges or suppress internal RFC1918 blocks.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Phishing: Spear-phishing via Service |
| Technique ID | T1566.004 |
| Secondary Technique | Forced Authentication (PetitPotam) |
| Secondary Technique ID | T1187 |
| Tertiary Technique | Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay |
| Tertiary Technique ID | T1557.001 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Delivery |
| Exploitation |
| Command & Control (C2) |

## Splunk Detection Query

### Query 1 — RMM Execution with Elevated Risk When Parent Is Browser or Teams

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name IN (
    "AnyDesk.exe", "TeamViewer.exe", "ScreenConnect.exe", "Splashtop.exe",
    "LogMeIn.exe", "GoToAssist.exe", "BeyondTrust.exe", "Atera.exe",
    "TacticalRMM.exe", "NinjaRMM.exe", "DWAgent.exe", "rustdesk.exe",
    "quickassist.exe", "msra.exe"
  )
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    lower(parent_process_name) IN ("teams.exe", "ms-teams.exe", "msedge.exe", "chrome.exe", "firefox.exe"), 90,
    lower(parent_process_name) IN ("explorer.exe", "cmd.exe", "powershell.exe"), 75,
    1=1, 55)
| where risk_score >= 55
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score
```

### Query 2 — Outbound SMB to Non-RFC1918 Destinations (PetitPotam Relay Indicator)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.dest_port=445 All_Traffic.transport=tcp
  NOT All_Traffic.dest_ip IN ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16")
by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(1=1, 85)
| table firstTime lastTime src_ip dest_ip dest_port app risk_score
```

### Query 3 — Spring Ring IOC Match: Known Attacker IPs

```spl
index=* (src_ip IN ("193.32.248.251", "185.65.134.209") OR dest_ip IN ("193.32.248.251", "185.65.134.209"))
| stats count min(_time) as firstTime max(_time) as lastTime by src_ip dest_ip _indextime sourcetype
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=100
| table firstTime lastTime src_ip dest_ip sourcetype risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| RMM spawned directly from Teams, Edge, Chrome, or Firefox | 90 | Social-engineering delivery path — no legitimate IT flow spawns RMM from browser |
| RMM spawned from Explorer, cmd.exe, or PowerShell | 75 | Suspicious but legitimate admin deployments possible |
| RMM executed with any other parent | 55 | Context enrichment, correlate with Teams audit logs |
| Outbound SMB/445 to non-RFC1918 destination | 85 | Near-never legitimate; strong relay or worm indicator |
| Traffic to/from known Spring Ring attacker IPs | 100 | Direct IOC match — confirmed malicious infrastructure |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Spring Ring (unnamed group, Unit 42 tracking) | [Unit 42 Report](https://unit42.paloaltonetworks.com/spring-ring-voice-phishing-campaigns/) |

## References

- [Unit 42: Spring Ring Voice Phishing Campaigns](https://unit42.paloaltonetworks.com/spring-ring-voice-phishing-campaigns/)
- [MITRE ATT&CK T1566.004 — Phishing: Spear-phishing via Service](https://attack.mitre.org/techniques/T1566/004/)
- [MITRE ATT&CK T1187 — Forced Authentication](https://attack.mitre.org/techniques/T1187/)
- [MITRE ATT&CK T1557.001 — Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay](https://attack.mitre.org/techniques/T1557/001/)
- [MITRE ATT&CK T1219 — Remote Access Software](https://attack.mitre.org/techniques/T1219/)
- [PetitPotam — CERT-FR Advisory](https://www.cert.ssi.gouv.fr/actualite/CERTFR-2021-ACT-035/)
- [Microsoft: Mitigating NTLM Relay Attacks on Active Directory Certificate Services](https://support.microsoft.com/en-us/topic/kb5005413-mitigating-ntlm-relay-attacks-on-active-directory-certificate-services-ad-cs-3612b773-4043-4aa9-b23d-b87910cd3429)
