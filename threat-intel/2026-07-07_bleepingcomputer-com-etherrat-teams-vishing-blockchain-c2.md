---
scraped_at: "2026-07-07T00:00:00Z"
source_url: "https://www.bleepingcomputer.com/news/security/fake-it-support-calls-on-microsoft-teams-push-etherrat-malware/"
report_type: threat-intel
severity: high
title: "EtherRAT: Teams Vishing Campaign Delivers Cross-Platform RAT with Ethereum Smart Contract C2"
---

# EtherRAT: Teams Vishing Campaign Delivers Cross-Platform RAT with Ethereum Smart Contract C2

**Source:** BleepingComputer / Palo Alto Networks Unit 42  
**Published:** 2026-07-06  
**Severity:** High  
**Tactic:** Initial Access (TA0001), Execution (TA0002), Command and Control (TA0011)

---

## 1. IOCs

### Domains

| Indicator | Type | Notes |
|-----------|------|-------|
| `camorreado[.]click` | Domain | EtherRAT MSI distribution server; open directory listing confirmed with versioned installer files `v1.msi` through `v9.msi`; active development indicated |

### Files

| Indicator | Type | Notes |
|-----------|------|-------|
| `v1.msi` – `v9.msi` | Filename pattern | Versioned MSI installers hosted on `camorreado[.]click`; no SHA-256 hashes published |

No traditional C2 IP addresses. EtherRAT retrieves its active C2 address from an Ethereum smart contract — sinkholing or IP blocking is ineffective without disabling the smart contract itself.

---

## 2. TTPs

| MITRE Tactic | Tactic ID | Technique | Technique ID | Usage |
|--------------|-----------|-----------|--------------|-------|
| Initial Access | TA0001 | Phishing: Spearphishing via Service | T1566.003 | Microsoft Teams voice call from external attacker account impersonating IT support; victim directed to install "troubleshooting tool" |
| Initial Access | TA0001 | Phishing | T1566 | Initial phishing email with "Employee Survey" PDF lure establishes contact before Teams call |
| Execution | TA0002 | User Execution: Malicious File | T1204.002 | Victim downloads and executes MSI installer from `camorreado[.]click` under IT support pretext |
| Execution | TA0002 | Command and Scripting Interpreter | T1059 | MSI drops legitimate Node.js runtime; decrypts embedded EtherRAT payload and launches it |
| Persistence | TA0003 | Boot or Logon Autostart Execution | T1547 | EtherRAT installs persistence mechanism on victim host |
| Command and Control | TA0011 | Application Layer Protocol: Web Protocols | T1071.001 | EtherRAT communicates with C2 retrieved from Ethereum smart contract (EtherHiding technique) |
| Command and Control | TA0011 | Dynamic Resolution | T1568 | Active C2 address stored in Ethereum smart contract; attacker can rotate C2 infrastructure by updating contract data without redeploying malware |
| Collection | TA0009 | Data from Local System | T1005 | EtherRAT collects credentials, files, and system data |
| Exfiltration | TA0010 | Exfiltration Over C2 Channel | T1041 | Data exfiltrated via EtherRAT C2 connection |

---

## 3. Malware & Tools

### EtherRAT

- **Type:** Cross-platform Remote Access Trojan (RAT)
- **Language:** Node.js
- **Delivery:** MSI installer drops legitimate Node.js runtime + encrypted payload; payload decrypted and launched at install time
- **C2 mechanism:** EtherHiding — active C2 IP/domain retrieved from an Ethereum smart contract; defeating traditional sinkholing and IP blocklisting
- **Capabilities:** Full command execution, file manipulation, data theft, credential harvesting, persistence
- **Distribution server:** `camorreado[.]click` (open directory with versioned MSI files `v1.msi`–`v9.msi` indicating active development)

### Attack Chain

```
Phishing email ("Employee Survey" PDF lure)
  └→ Microsoft Teams call from external account impersonating "System Administrator"
       └→ Social engineering: victim instructed to install "troubleshooting tool"
            └→ Victim downloads MSI from camorreado[.]click (v1.msi – v9.msi)
                 └→ MSI executes:
                      ├→ Drops legitimate Node.js runtime
                      ├→ Decrypts embedded EtherRAT payload
                      └→ Launches EtherRAT
                           └→ EtherRAT queries Ethereum smart contract → retrieves active C2
                                └→ Persistent remote access established
```

### Prior Coverage

- **DFIR Report, May 11, 2026:** EtherRAT + TukTuk C2 leading to deployment of The Gentleman Ransomware
- **Malwarebytes, June 2026:** Full delivery infrastructure mapping

---

## 4. Threat Actor Profile

| Attribute | Detail |
|-----------|--------|
| Attribution | Unknown; no formal APT/nation-state attribution |
| Motivation | Likely financially motivated; prior EtherRAT deployments have led to ransomware (The Gentleman Ransomware per DFIR Report May 2026) |
| Target profile | Enterprise employees; campaign targets via Teams impersonation of IT support |
| Infrastructure | Distribution server: `camorreado[.]click`; C2: Ethereum smart contract (blockchain-resident) |
| Evasion | Ethereum-based C2 prevents traditional IP/domain blocking; Node.js + encrypted payload bypasses AV at delivery stage |

---

## 5. Splunk Detection Searches

### Search 1 — DNS: Resolution of EtherRAT Distribution Domain

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Resolution.DNS
  where DNS.query="camorreado.click" OR DNS.query="*.camorreado.click"
  by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| eval risk_score=95
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime src query answer risk_score
```

Detects DNS lookups for the confirmed EtherRAT distribution server.

### Search 2 — Process: msiexec.exe Spawning Node.js (EtherRAT Delivery Pattern)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name="msiexec.exe"
    AND (Processes.process_name="node.exe" OR Processes.process_name="node")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| eval risk_score=85
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

Detects `msiexec.exe` spawning a `node.exe` process — the execution pattern when an EtherRAT MSI installer drops and launches the Node.js RAT payload.

### Search 3 — Network: Outbound Connections to Ethereum/Blockchain RPC Endpoints from Endpoints

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_port IN (8545,8546,30303)
    OR All_Traffic.dest IN ("mainnet.infura.io","rpc.ankr.com","eth-mainnet.g.alchemy.com",
                             "cloudflare-eth.com","api.trongrid.io","fullnode.mainnet.aptoslabs.com")
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| where NOT (app IN ("chrome","firefox","msedge","safari"))
| eval risk_score=75
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime src dest dest_port app risk_score
```

Detects endpoint processes connecting to Ethereum/blockchain RPC APIs — suspicious when not from a browser. EtherRAT uses these to retrieve its active C2 address from smart contract storage (EtherHiding). Note: legitimate enterprise endpoints rarely make direct blockchain RPC calls.

### Search 4 — Teams Vishing: External Teams Users Initiating Voice Calls (Pre-Compromise Signal)

```spl
index=o365 Workload=MicrosoftTeams Operation IN ("CallStarted","MeetingCreated")
| where isnotnull(ExternalParticipantCount) AND ExternalParticipantCount > 0
| rex field=_raw "\"UserAgent\":\s*\"(?P<user_agent>[^\"]+)\""
| stats count min(_time) as firstTime max(_time) as lastTime, 
        values(UserId) as initiators, values(ParticipantInfo) as participants
  by ExternalParticipantCount, user_agent
| eval risk_score=if(match(initiators, "(?i)system.admin|it.support|helpdesk"), 75, 50)
| where risk_score >= 50
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime initiators participants ExternalParticipantCount risk_score
```

Detects unsolicited inbound Teams voice calls from external accounts — an early signal for vishing campaigns that use IT support impersonation to deliver malware. Requires Microsoft 365 audit log forwarding.

---

## 6. Executive Summary

On July 6, 2026, BleepingComputer and Palo Alto Networks Unit 42 reported an active campaign delivering EtherRAT — a cross-platform Node.js RAT — via Microsoft Teams vishing calls impersonating IT support. The attack flow begins with a phishing email ("Employee Survey" PDF) to establish initial contact, followed by a Teams call from an external account claiming to be a "System Administrator." The victim is socially engineered into downloading a malicious MSI installer from `camorreado[.]click`, which drops a legitimate Node.js runtime and decrypts an embedded EtherRAT payload.

The critical differentiator in this campaign is EtherRAT's use of **EtherHiding** — the active C2 server address is stored in an Ethereum smart contract. The malware queries the blockchain to retrieve its current C2 endpoint, making traditional IP and domain blocklisting ineffective. The distribution server (`camorreado[.]click`) shows an open directory with versioned installer files (`v1.msi`–`v9.msi`), confirming active development.

Prior DFIR Report research (May 2026) documented EtherRAT leading to The Gentleman Ransomware deployment, indicating this RAT is used as a pre-ransomware access tool. Defenders should implement DNS blocking of `camorreado[.]click`, monitor for `msiexec.exe` spawning `node.exe`, and watch for outbound endpoint connections to Ethereum RPC APIs — an unusual pattern that indicates potential EtherHiding C2 activity.

---

## References

- [BleepingComputer — Fake IT Support Calls on Microsoft Teams Push EtherRAT Malware (2026-07-06)](https://www.bleepingcomputer.com/news/security/fake-it-support-calls-on-microsoft-teams-push-etherrat-malware/)
- [DFIR Report — EtherRAT + The Gentleman Ransomware (2026-05-11)](https://thedfirreport.com/)
- [Malwarebytes — EtherRAT Infrastructure Analysis (2026-06)](https://www.malwarebytes.com/blog/)
- [MITRE ATT&CK — T1566.003: Phishing via Service](https://attack.mitre.org/techniques/T1566/003/)
- [MITRE ATT&CK — T1568: Dynamic Resolution](https://attack.mitre.org/techniques/T1568/)
- [MITRE ATT&CK — T1071.001: Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
