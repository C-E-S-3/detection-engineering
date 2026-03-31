---
scraped_at: "2026-03-31T13:53:04-04:00"
source_url: "https://www.bleepingcomputer.com/news/security/cisco-source-code-stolen-in-trivy-linked-dev-environment-breach/"
report_type: threat-intel
---

## 1. Indicators of Compromise (IOCs)

### IP Addresses
- None identified.

### Domains/URLs
- None identified.

### File Hashes
- None identified.

### AWS Keys
- Multiple AWS keys were reportedly stolen and used for unauthorized activities in Cisco AWS accounts. Specific keys were not disclosed.

### Other IOCs
- Malicious GitHub Action plugin used to steal credentials and data from Cisco's build and development environment.

## 2. TTPs (MITRE ATT&CK Mapping)

### Initial Access
- **T1195.002 - Supply Chain Compromise**: Threat actors exploited a vulnerability in the Trivy vulnerability scanner's GitHub pipeline to distribute credential-stealing malware.

### Credential Access
- **T1552.001 - Credentials in Files**: Stolen credentials from the Trivy supply chain attack were used to access Cisco's internal development environment.

### Impact
- **T1485 - Data Destruction**: Cisco isolated and reimaged affected systems to mitigate the breach.
- **T1530 - Data from Cloud Storage Object**: Stolen AWS keys were used to perform unauthorized activities in Cisco's AWS accounts.
- **T1074.001 - Local Data Staging**: Attackers cloned over 300 GitHub repositories, including source code for AI-powered products and unreleased projects.

## 3. Malware & Tools

### Malware
- **TeamPCP Cloud Stealer**: An information-stealing malware linked to the TeamPCP threat group, used in the Trivy supply chain attack.

### Tools
- **Malicious GitHub Action Plugin**: Used to steal credentials and data from Cisco's development environment.

## 4. Threat Actor / Campaign Attribution

### Threat Actor
- **TeamPCP**: A threat group conducting supply chain attacks targeting developer platforms such as GitHub, PyPi, NPM, and Docker. They are linked to the Trivy vulnerability scanner breach and other supply chain attacks.

### Campaigns
- **Trivy Supply Chain Attack**: Exploited Trivy's GitHub pipeline to distribute credential-stealing malware.
- **LiteLLM and Checkmarx Supply Chain Attacks**: Follow-on attacks impacting additional organizations and platforms.

### Targeted Sectors/Geographies
- Cisco's corporate customers, including banks, BPOs, and US government agencies.

## 5. Splunk Detection Searches

### Detecting Malicious GitHub Actions
```spl
index=github_logs sourcetype=github:actions "malicious GitHub Action"
| stats count by actor, repo, action
| table actor repo action count
```

### Detecting Unauthorized AWS Key Usage
```spl
index=aws sourcetype=aws:cloudtrail eventName=ConsoleLogin
| search errorCode=AccessDenied
| stats count by userIdentity.arn, sourceIPAddress, eventTime
| table userIdentity.arn sourceIPAddress eventTime count
```

### Detecting Credential Theft from Trivy
```spl
index=malware sourcetype=endpoint_logs "TeamPCP Cloud Stealer"
| stats count by file_path, process_name, user
| table file_path process_name user count
```

### Monitoring GitHub Repository Cloning
```spl
index=github_logs sourcetype=github:repo "clone"
| stats count by repo_name, actor, ip_address
| table repo_name actor ip_address count
```

## 6. Executive Summary

Cisco has suffered a significant breach of its internal development environment due to a supply chain attack on the Trivy vulnerability scanner. Threat actors, identified as the TeamPCP group, used a malicious GitHub Action plugin to steal credentials and data, impacting over 300 GitHub repositories, including sensitive source code for AI-powered products and customer projects. The attackers also exploited stolen AWS keys to perform unauthorized activities in Cisco's AWS accounts. Immediate actions should include reviewing and rotating credentials, monitoring for unauthorized access to cloud accounts, and implementing additional security controls for CI/CD pipelines.