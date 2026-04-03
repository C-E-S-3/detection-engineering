# Credential and Secrets Harvesting — Cloud Tokens, SSH Keys, and Environment Variables

## Description

Detects automated collection of credentials and secrets from common storage locations: SSH private keys, cloud provider tokens (AWS, GCP, Azure), Kubernetes service account tokens, Docker registry credentials, environment variable files (.env), and shell history. This pattern is the hallmark of modern supply chain attacks (TeamPCP Trivy/Telnyx compromise), cloud credential theft operations (UAT-10608 NEXUS Listener), and post-exploit credential harvesting in CI/CD environments. Distinct from interactive credential dumping — this targets static files and environment-exported secrets. Common false positives: legitimate backup agents, configuration management tools (Ansible, Puppet); exclude known backup service accounts and configuration management processes.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Collection |
| Tactic ID | TA0009 |
| Technique | Data from Local System |
| Technique ID | T1005 |

Secondary techniques: T1552.001 (Unsecured Credentials: Credentials in Files), T1552.007 (Container API — Kubernetes secrets), T1074.001 (Data Staged: Local Data Staging)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Actions on Objectives |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.action="read"
    AND (Filesystem.file_path="*/.ssh/id_rsa*" OR Filesystem.file_path="*/.ssh/id_ed25519*"
         OR Filesystem.file_path="*/.aws/credentials*" OR Filesystem.file_path="*/.aws/config*"
         OR Filesystem.file_path="*/.gcp/credentials.json*"
         OR Filesystem.file_path="*/.kube/config*"
         OR Filesystem.file_path="*/.docker/config.json*"
         OR Filesystem.file_path="*/.env" OR Filesystem.file_path="*/.env.local"
         OR Filesystem.file_path="*/service-account*.json"
         OR Filesystem.file_path="*/token" OR Filesystem.file_path="*/serviceaccount/token")
    AND NOT Filesystem.process_name IN ("ssh","ssh-agent","aws","kubectl","docker",
        "gcloud","terraform","vault","ansible","puppet","chef","sshd","git")
  by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path
| `drop_dm_object_name(Filesystem)`
| eval risk_score=case(
    match(file_path, "/\.kube/config|serviceaccount/token"), 90,
    match(file_path, "/\.ssh/id_rsa|/\.ssh/id_ed25519"), 85,
    match(file_path, "/\.aws/credentials|/\.gcp/|service-account"), 85,
    match(file_path, "/\.docker/config|\.env$"), 75,
    1=1, 65)
| where risk_score >= 65
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user process_name file_path risk_score
```

**Supplemental: Environment variable exfiltration (Linux/macOS)**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.process="*printenv*" OR Processes.process="*env*|*curl*"
         OR Processes.process="*export*AWS*" OR Processes.process="*export*TOKEN*"
         OR Processes.process="*export*SECRET*" OR Processes.process="*/proc/*/environ*")
    AND Processes.process_name IN ("bash","sh","python","python3","perl","ruby")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| eval risk_score=case(
    match(process, "(?i)/proc/\\d+/environ"), 90,
    match(process, "(?i)printenv.*curl|env.*curl|export.*SECRET|export.*TOKEN"), 85,
    1=1, 70)
| where risk_score >= 70
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

**Supplemental: Shell history and credential file bulk collection**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process="*bash_history*" OR Processes.process="*zsh_history*"
     OR (Processes.process_name IN ("tar","zip","7z") AND
         (Processes.process="*ssh*" OR Processes.process="*aws*" OR Processes.process="*kube*"))
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| eval risk_score=case(
    match(process_name, "(?i)tar|zip|7z") AND match(process, "(?i)ssh|aws|kube"), 85,
    match(process, "bash_history|zsh_history"), 70,
    1=1, 60)
| where risk_score >= 70
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Non-standard process reading Kubernetes service account token | 90 | Container breakout or pod compromise; only kube-system processes should touch this |
| SSH private key read by non-SSH process | 85 | Key theft for lateral movement; ssh/git are the only legitimate consumers |
| AWS/GCP credentials read by scripting engine | 85 | Cloud pivot; attackers harvest these for lateral movement to cloud infra |
| Environment variables piped to curl/network tool | 85 | Live credential exfiltration pattern from UAT-10608/TeamPCP campaigns |
| Docker config read by non-Docker process | 75 | Registry credential theft; enables supply chain compromise of container images |
| Shell history or credential archives | 70-85 | Bulk collection before exfiltration staging |

## Associated Threat Actors

| Actor | Relationship to Detection |
|-------|--------------------------|
| UAT-10608 | Primary campaign pattern: NEXUS Listener framework exfiltrates SSH keys, cloud tokens, K8s secrets, and env vars from CVE-2025-55182-compromised hosts |
| TeamPCP | Trivy/Telnyx/Axios supply chain attacks harvest CI/CD credentials from GitHub Actions runners |
| UNC5221 | SPAWN ecosystem targets Ivanti VPN appliances to harvest admin credentials and session tokens |
| CrystalRAT | Infostealer targeting browser credentials, Steam, Discord, Telegram alongside clipboard hijacking |
| Lazarus Group (HIDDEN COBRA) | Long-standing credential harvesting targeting cryptocurrency exchange API keys and SSH keys |

## References

- [Cisco Talos - UAT-10608 Automated Credential Harvesting](https://blog.talosintelligence.com/uat-10608-inside-a-large-scale-automated-credential-harvesting-operation-targeting-web-applications/)
- [CrowdStrike - Trivy Action Supply Chain Compromise](https://www.crowdstrike.com/en-us/blog/from-scanner-to-stealer-inside-the-trivy-action-supply-chain-compromise/)
- [MITRE ATT&CK - T1552.001 Unsecured Credentials: Credentials in Files](https://attack.mitre.org/techniques/T1552/001/)
- [MITRE ATT&CK - T1005 Data from Local System](https://attack.mitre.org/techniques/T1005/)
