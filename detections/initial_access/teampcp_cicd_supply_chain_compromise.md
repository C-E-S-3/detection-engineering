# TeamPCP CI/CD Supply Chain Compromise — Backdoored GitHub Actions and PyPI Packages

## Description

Detects the supply chain attack pattern used by TeamPCP, a threat actor responsible for compromising the `aquasecurity/trivy-action` GitHub Action, the Telnyx PyPI package, and the LiteLLM Python library. TeamPCP repoints mutable Git tags to malicious commits or uploads backdoored PyPI package versions, injecting credential-stealing code that harvests SSH keys, cloud tokens, Kubernetes secrets, and environment variables, then exfiltrates to attacker-controlled infrastructure (including ICP blockchain C2). On CI/CD runners, the malicious `entrypoint.sh` executes Python scripts that encrypt and POST stolen data to typosquatted exfiltration domains. Common false positives: legitimate CI/CD tools downloading dependencies; detect based on unusual data volumes and destinations from runner hosts.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Supply Chain Compromise: Compromise Software Supply Chain |
| Technique ID | T1195.002 |

Secondary techniques: T1552.001 (Unsecured Credentials — cloud tokens/SSH keys), T1041 (Exfiltration Over C2), T1027 (Obfuscation — AES-256-CBC/RSA encrypted payloads), T1070.004 (File Deletion — cleanup of temporary files)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Delivery |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_ip IN ("scan.aquasecurtiy.org") OR All_Traffic.dest_domain IN ("scan.aquasecurtiy.org", "tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io")
  by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| eval risk_score=95
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime src_ip dest_ip dest_port app risk_score
```

**Supplemental: CI/CD runner — credential file access from Python process**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.process_name IN ("python", "python3", "python2")
    AND (Filesystem.file_path="*/.ssh/*" OR Filesystem.file_path="*/.aws/*"
         OR Filesystem.file_path="*/.kube/config*" OR Filesystem.file_path="*/.docker/config.json*"
         OR Filesystem.file_path="/home/runner/*")
    AND Filesystem.action="read"
  by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path
| `drop_dm_object_name(Filesystem)`
| eval risk_score=case(
    match(file_path, "/\.kube/config|service-account"), 90,
    match(file_path, "/\.ssh/"), 85,
    match(file_path, "/\.aws/|/\.docker/"), 80,
    1=1, 65)
| where risk_score >= 65
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user process_name file_path risk_score
```

**Supplemental: Malicious PyPI package installation — fs-loader.com callback**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_domain="fs-loader.com"
  by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.uri_path
| `drop_dm_object_name(All_Traffic)`
| eval risk_score=90
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime src_ip dest_ip dest_port uri_path risk_score
```

**Supplemental: Wave 3 (May 2026) — durabletask dropper and GitHub Actions C2 exfiltration**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_domain IN ("filev2.getsession.org","api.masscan.cloud")
  by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_domain All_Traffic.dest_port
| `drop_dm_object_name(All_Traffic)`
| eval risk_score=95
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime src_ip dest_ip dest_domain dest_port risk_score
```

**Supplemental: Suspicious process in GitHub Actions runner temp directories**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.process="/home/runner/_work/_temp/*.sh"
         OR Processes.process="*/.config/sysmon.py*"
         OR Processes.parent_process_name="bash"
            AND Processes.process="*entrypoint.sh*")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| eval risk_score=case(
    match(process, "sysmon\.py"), 90,
    match(process, "/home/runner/_work/_temp/.*\.sh"), 75,
    1=1, 60)
| where risk_score >= 60
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Traffic to `scan.aquasecurtiy.org` or ICP blockchain C2 | 95 | Confirmed exfil endpoints from TeamPCP Trivy Action campaign |
| Traffic to `fs-loader.com` | 90 | TeamPCP C2 hosting malicious WAV payloads (Telnyx/Axios campaigns) |
| Traffic to `filev2.getsession.org` or `api.masscan.cloud` | 95 | Wave 3 exfil endpoints from durabletask PyPI compromise (May 2026) |
| Python reading `.kube/config` or service account tokens | 90 | K8s token theft; legitimate CI tools don't read kubeconfig from Python install hooks |
| Python reading `.ssh/` or `.aws/` credentials | 80-85 | Credential harvesting pattern from install-time malicious code |
| Temp shell scripts from GitHub Actions runner paths | 75 | Malicious workflow injection; correlate with unusual network destinations |
| `~/.config/sysmon.py` execution | 90 | Loader persistence from Trivy campaign; legitimate sysmon is not Python |

## Associated Threat Actors

| Actor | Relationship to Detection |
|-------|--------------------------|
| TeamPCP | Primary actor; supply chain specialist known for compromising Trivy Action (GitHub Actions), Telnyx PyPI SDK, and LiteLLM; targets CI/CD credential theft at scale |

## References

- [CrowdStrike - From Scanner to Stealer: Trivy Action Supply Chain Compromise](https://www.crowdstrike.com/en-us/blog/from-scanner-to-stealer-inside-the-trivy-action-supply-chain-compromise/)
- [BleepingComputer - Backdoored Telnyx PyPI Package Pushes Malware](https://www.bleepingcomputer.com/news/security/backdoored-telnyx-pypi-package-pushes-malware-hidden-in-wav-audio/)
- [BleepingComputer - Hackers Compromise Axios npm Package](https://www.bleepingcomputer.com/news/security/hackers-compromise-axios-npm-package-to-drop-cross-platform-malware/)
- [MITRE ATT&CK - T1195.002 Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/002/)
- [Wiz — durabletask TeamPCP Supply Chain Attack (Wave 3)](https://www.wiz.io/blog/durabletask-teampcp-supply-chain-attack)
- [BleepingComputer — GitHub investigates internal repo breach by TeamPCP](https://www.bleepingcomputer.com/news/security/github-investigates-internal-repositories-breach-claimed-by-teampcp/)
