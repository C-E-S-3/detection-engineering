# BlueNoroff FaceStealer PowerShell-Spawned SSH Backdoor

## Description

Detects OpenSSH binaries (ssh.exe, sshd.exe) spawned by PowerShell, cmd.exe, or other scripting interpreters on Windows hosts. This is the primary persistence mechanism used by BlueNoroff's FaceStealer campaign: after a ClickFix-style paste-and-execute PowerShell payload runs in memory, it activates or installs the Windows OpenSSH optional feature and starts the SSH daemon as a backdoor, appending the actor's public key to the victim's authorized_keys. Legitimate OpenSSH usage on Windows should be initiated by the SCM (services.exe) or the user directly, not by PowerShell or scripting engine parents.

False positives include automated developer environment provisioning scripts (Ansible, Chef, cloud-init) that explicitly start SSH via PowerShell. These should be allowlisted by host name or user account.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Persistence |
| Tactic ID | TA0003 |
| Technique | Server Software Component: SSH |
| Technique ID | T1505.004 |
| Secondary Tactic | Lateral Movement |
| Secondary Technique ID | T1021.004 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Installation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.process_name="ssh.exe" OR Processes.process_name="sshd.exe"
         OR Processes.process_name="OpenSSH.exe" OR Processes.process_name="ssh-agent.exe")
  AND (Processes.parent_process_name="powershell.exe" OR Processes.parent_process_name="pwsh.exe"
       OR Processes.parent_process_name="cmd.exe" OR Processes.parent_process_name="wscript.exe"
       OR Processes.parent_process_name="cscript.exe" OR Processes.parent_process_name="mshta.exe"
       OR Processes.parent_process_name="rundll32.exe" OR Processes.parent_process_name="regsvr32.exe")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    parent_process_name IN ("powershell.exe","pwsh.exe"), 90,
    parent_process_name IN ("wscript.exe","cscript.exe","mshta.exe"), 90,
    parent_process_name IN ("rundll32.exe","regsvr32.exe"), 85,
    1=1, 80)
| where risk_score >= 80
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| SSH binary spawned by PowerShell/pwsh | 90 | High confidence malicious: no legitimate management scenario spawns SSH this way |
| SSH binary spawned by wscript/cscript/mshta | 90 | Script engine parent is a strong indicator of attacker-controlled execution |
| SSH binary spawned by rundll32/regsvr32 | 85 | LOLBin parent is anomalous but slightly lower confidence |
| SSH binary spawned by cmd.exe | 80 | Could be a one-liner installation script; still worth investigating |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| BlueNoroff / APT38 | [MITRE ATT&CK G0098](https://attack.mitre.org/groups/G0098/) |
| Sapphire Sleet (Microsoft) | [Microsoft Threat Actor Profile](https://www.microsoft.com/en-us/security/blog/threat-intelligence/sapphire-sleet/) |
| Stardust Chollima (CrowdStrike) | [CrowdStrike Adversary Profile](https://www.crowdstrike.com/adversaries/stardust-chollima/) |

## References

- [BleepingComputer - FBI Disrupts BlueNoroff FaceStealer](https://www.bleepingcomputer.com/news/security/fbi-disrupts-bluenoroff-facestealer-operation-targeting-crypto-web3/)
- [IC3 Cyber Security Advisory CSA 261112](https://www.ic3.gov/CSA/2026/261112.pdf)
- [MITRE ATT&CK T1505.004 - SSH Backdoor](https://attack.mitre.org/techniques/T1505/004/)
- [MITRE ATT&CK T1021.004 - Remote Services: SSH](https://attack.mitre.org/techniques/T1021/004/)
- [CISA - TraderTraitor: North Korean APT Targets Blockchain Companies](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-108a)
