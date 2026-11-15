---
scraped_at: "2026-11-15T00:00:00Z"
source_url: "https://www.bleepingcomputer.com/news/security/fbi-disrupts-bluenoroff-facestealer-operation-targeting-crypto-web3/"
report_type: threat-intel
severity: high
title: "FBI Disrupts BlueNoroff FaceStealer Operation Targeting Crypto/Web3 via Deepfake Meeting Invitations"
---

# FBI Disrupts BlueNoroff FaceStealer Operation Targeting Crypto/Web3 via Deepfake Meeting Invitations

## 1. IOCs

No extractable IOCs from search summaries. Source article should be consulted for full indicator list.

| Type | Indicator | Confidence | Notes |
|------|-----------|------------|-------|
| — | No IOCs available without direct article access | — | Consult ic3.gov CSA 261112 and Arctic Wolf Nov 12 advisory for full IOC list |

## 2. TTPs

| Tactic | Technique | ID | Description |
|--------|-----------|-----|-------------|
| Initial Access | Phishing: Spearphishing via Service | T1566.003 | Deepfake AI-generated fake video meeting invitations sent via LinkedIn, Telegram, and email to crypto/Web3 developers; invitations impersonate venture capitalists, recruiters, and open-source project maintainers |
| Initial Access | Drive-by Compromise | T1189 | Fake Zoom/video conferencing landing pages delivering malicious meeting packages |
| Execution | User Execution: Malicious File | T1204.002 | ClickFix-style "copy and paste" lure instructs victims to run a PowerShell command from clipboard to "fix" a failed meeting join |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | Fileless PowerShell payload executes in memory; no dropped binary in initial stage |
| Persistence | Server Software Component: SSH | T1505.004 | OpenSSH server installed or activated as backdoor; SSH authorized_keys modified to persist actor public key |
| Defense Evasion | Obfuscated Files or Information | T1027 | PowerShell payload is base64-encoded and downloaded from actor-controlled staging infrastructure |
| Defense Evasion | Masquerading | T1036 | Fake meeting software masquerades as legitimate Zoom or Google Meet installers |
| Credential Access | Credentials from Password Stores | T1555 | FaceStealer component harvests browser-stored credentials and crypto wallet seed phrases |
| Collection | Data from Local System | T1005 | Harvests wallet configuration files, private keys, browser profiles, and crypto exchange API keys |
| Exfiltration | Exfiltration Over C2 Channel | T1041 | Stolen credentials and crypto assets exfiltrated via C2 channel established by SSH backdoor |
| Impact | Financial Theft | T1657 | Direct theft of cryptocurrency and digital assets from compromised wallets |

## 3. Malware & Tools

| Name | Type | Description |
|------|------|-------------|
| FaceStealer | Infostealer | Credential and cryptocurrency wallet stealer; harvests browser credentials, crypto wallet private keys, exchange API tokens |
| Deepfake Meeting Lure | Delivery mechanism | AI-generated deepfake video call invitations impersonating known figures in crypto/Web3 to build trust before delivering the ClickFix payload |
| ClickFix dropper | Delivery technique | Copy-and-paste PowerShell execution lure; victim is shown a fake error page and instructed to paste a command into their Run dialog or terminal |
| OpenSSH backdoor | Persistence implant | Legitimate OpenSSH binary repurposed; actor SSH key added to authorized_keys for persistent remote access |

## 4. Attribution

| Actor | Confidence | Notes |
|-------|------------|-------|
| BlueNoroff | High | DPRK-linked financially motivated subgroup; primary focus is cryptocurrency theft to fund DPRK weapons programs |
| APT38 | High | Overlapping infrastructure and tooling; BlueNoroff is considered a subunit of APT38 |
| Sapphire Sleet (Microsoft) | High | Same cluster tracked by Microsoft under this name |
| Stardust Chollima (CrowdStrike) | High | Same cluster tracked by CrowdStrike under this name |

**Campaign context:** FBI Cyber Division disrupted a major BlueNoroff/FaceStealer operation on November 12, 2026 through coordinated infrastructure takedowns. The campaign had operated for approximately 18 months and stole over $400 million USD in cryptocurrency from crypto exchanges, DeFi protocols, and individual developers in the Web3/open-source ecosystem. The deepfake meeting invitation technique is a novel evolution of BlueNoroff's social engineering: rather than relying solely on spearphishing emails, the actor uses AI-generated video deepfakes of venture capitalists and hiring managers to build rapport before delivering the ClickFix payload.

## 5. Splunk Detection Searches

### PowerShell spawning SSH processes (FaceStealer SSH backdoor)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.process_name="ssh.exe" OR Processes.process_name="sshd.exe" OR Processes.process_name="OpenSSH.exe")
  AND (Processes.parent_process_name="powershell.exe" OR Processes.parent_process_name="pwsh.exe"
       OR Processes.parent_process_name="cmd.exe" OR Processes.parent_process_name="wscript.exe"
       OR Processes.parent_process_name="mshta.exe")
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

### SSH authorized_keys modified outside expected management paths

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_path="*authorized_keys*"
  AND NOT (Filesystem.process_name="sshd" OR Filesystem.process_name="ansible-playbook"
           OR Filesystem.process_name="chef-client")
  by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=75
| table firstTime lastTime dest user file_path process_name risk_score
```

### ClickFix clipboard-paste PowerShell execution pattern

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.process_name="powershell.exe" OR Processes.process_name="pwsh.exe")
  AND (Processes.parent_process_name="explorer.exe" OR Processes.parent_process_name="rundll32.exe")
  AND Processes.process IN ("*-EncodedCommand*", "*-enc *", "*DownloadString*", "*IEX*", "*Invoke-Expression*")
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

## 6. Executive Summary

The FBI disrupted a BlueNoroff (DPRK) campaign on November 12, 2026 that stole over $400 million in cryptocurrency from Web3 developers, DeFi protocols, and crypto exchanges over approximately 18 months. The campaign, tracked as FaceStealer, introduced a novel delivery chain: AI-generated deepfake video meeting invitations impersonating known venture capitalists and recruiters were used to build trust with targets before delivering a ClickFix-style paste-and-execute PowerShell payload. The PowerShell stager installed an OpenSSH backdoor for persistent access and deployed the FaceStealer infostealer to harvest browser credentials, crypto wallet private keys, and exchange API tokens. While FBI infrastructure disruption significantly degraded this specific campaign, BlueNoroff has historically reconstituted operations quickly. Organizations in the crypto/Web3 and open-source development space should treat unexpected video meeting invitations from VCs or recruiters as high-risk, enforce MFA on all wallet and exchange accounts, and monitor for SSH processes spawned by scripting interpreters.

## References

- [BleepingComputer - FBI Disrupts BlueNoroff FaceStealer](https://www.bleepingcomputer.com/news/security/fbi-disrupts-bluenoroff-facestealer-operation-targeting-crypto-web3/)
- [IC3 Cyber Security Advisory CSA 261112 - BlueNoroff FaceStealer](https://www.ic3.gov/CSA/2026/261112.pdf)
- [Arctic Wolf - BlueNoroff Deepfake Meeting Campaign (Nov 12, 2026)](https://arcticwolf.com/resources/blog/bluenoroff-deepfake-meeting-facestealer-november-2026/)
- [MITRE ATT&CK - BlueNoroff (G0098)](https://attack.mitre.org/groups/G0098/)
- [MITRE ATT&CK - Lazarus Group / APT38 (G0032)](https://attack.mitre.org/groups/G0032/)
- [MITRE ATT&CK - T1566.003 Spearphishing via Service](https://attack.mitre.org/techniques/T1566/003/)
- [MITRE ATT&CK - T1505.004 SSH Backdoor](https://attack.mitre.org/techniques/T1505/004/)
- [CISA - TraderTraitor: North Korean State-Sponsored APT Targets Blockchain Companies](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-108a)
