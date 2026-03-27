```markdown
---
scraped_at: 2026-03-20T00:00:00Z
source_url: https://www.crowdstrike.com/en-us/blog/from-scanner-to-stealer-inside-the-trivy-action-supply-chain-compromise/
report_type: threat-intel
---

# Threat Intelligence Report: Trivy-Action Supply Chain Compromise

## 1. Indicators of Compromise (IOCs)

### IP Addresses
- None identified.

### Domains and URLs
- `scan.aquasecurtiy[.]org` (typosquatted domain for exfiltration)
- `hxxps[://]tdtqy-oyaaa-aaaae-af2dq-cai[.]raw[.]icp0[.]io` (C2 hosted on ICP blockchain)

### File Hashes
- Malicious `entrypoint.sh` (SHA256): `18a24f83e807479438dcab7a1804c51a00dafc1d526698a66e0640d1e5dd671a`
- Legitimate `entrypoint.sh` (SHA256): `07500e81693c06ef7ac6bf210cff9c882bcc11db5f16b5bded161218353ba4da`

### Email Addresses
- None identified.

### File Names and Paths
- `/home/runner/_work/_temp/395479a1-…ded349.sh`
- `/home/runner/_work/_actions/aquasecurity/trivy-action/0.24.0/entrypoint.sh`
- `~/.config/sysmon.py`
- `/tmp/pglog`

### Registry Keys
- None identified.

### Mutex Names
- None identified.

### C2 Infrastructure Details
- C2 hosted on Internet Computer (ICP) blockchain: `hxxps[://]tdtqy-oyaaa-aaaae-af2dq-cai[.]raw[.]icp0[.]io`

## 2. TTPs (MITRE ATT&CK Mapping)

### Tactic: Initial Access
- **T1195.002 - Supply Chain Compromise**
  - The attacker compromised the GitHub repository of the `aquasecurity/trivy-action` and repointed tags to malicious commits.

### Tactic: Credential Access
- **T1552 - Unsecured Credentials**
  - The malicious script harvested credentials from environment variables, memory, and filesystem.

### Tactic: Exfiltration
- **T1041 - Exfiltration Over C2 Channel**
  - Data was encrypted and exfiltrated via HTTPS POST requests to a typosquatted domain and fallback via GitHub repositories.

### Tactic: Defense Evasion
- **T1070.004 - File Deletion**
  - Temporary files were removed to avoid detection.

- **T1027 - Obfuscated Files or Information**
  - Payloads were encrypted using AES-256-CBC and RSA keys.

### Tactic: Execution
- **T1059.004 - Command and Scripting Interpreter: Bash**
  - The malicious script executed via Bash on GitHub runners.

- **T1059.006 - Command and Scripting Interpreter: Python**
  - Base64-encoded Python scripts were used for credential harvesting.

### Tactic: Persistence
- **T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder**
  - The `~/.config/sysmon.py` script acted as a lightweight loader for persistence.

## 3. Malware & Tools

### Malware Families/Names
- Credential stealer embedded in `trivy-action` GitHub Action.
- `sysmon.py` loader script.

### Legitimate Tools Abused
- GitHub Actions CI/CD platform.

### Custom Tooling Descriptions
- Custom Python scripts for credential harvesting and encrypted exfiltration.

## 4. Threat Actor / Campaign Attribution

### Named Threat Groups
- None explicitly named.

### Campaign Names
- Trivy-Action Supply Chain Compromise.

### Known Affiliations or Motivations
- Likely espionage or financial gain through credential theft.

### Targeted Sectors and Geographies
- Organizations using GitHub Actions CI/CD pipelines globally.

## 5. Splunk Detection Searches

### Detecting Malicious Domain Access
```spl
index=proxy OR index=network
| search dest="scan.aquasecurtiy.org" OR dest="tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io"
| stats count by src_ip, dest, http_method, uri_path
| table src_ip, dest, http_method, uri_path, count
```
*# Detects connections to malicious domains used for exfiltration.*

### Detecting Execution of Malicious Scripts
```spl
index=oswin OR index=oslinux sourcetype=XmlWinEventLog OR sourcetype=sysmon
| search process_path IN ("/home/runner/_work/_temp/395479a1-…ded349.sh", "/home/runner/_work/_actions/aquasecurity/trivy-action/0.24.0/entrypoint.sh", "~/.config/sysmon.py", "/tmp/pglog")
| stats count by host, process_path, user, parent_process
| table host, process_path, user, parent_process, count
```
*# Detects execution of known malicious scripts.*

### Detecting GitHub Audit Log Events
```spl
index=github sourcetype=github:audit
| search action="pull_request_target"
| stats count by repo_name, actor, action
| table repo_name, actor, action, count
```
*# Identifies repositories using the vulnerable `pull_request_target` trigger.*

### Detecting Malicious File Hashes
```spl
index=endpoint sourcetype=crowdstrike:events:sensor
| search file_hash IN ("18a24f83e807479438dcab7a1804c51a00dafc1d526698a66e0640d1e5dd671a", "07500e81693c06ef7ac6bf210cff9c882bcc11db5f16b5bded161218353ba4da")
| stats count by file_name, file_path, file_hash
| table file_name, file_path, file_hash, count
```
*# Detects known malicious file hashes.*

### Detecting Encrypted Exfiltration
```spl
index=network sourcetype=firewall OR sourcetype=proxy
| search uri_path="tpcp.tar.gz"
| stats count by src_ip, dest_ip, uri_path
| table src_ip, dest_ip, uri_path, count
```
*# Detects exfiltration of encrypted payloads.*

## 6. Executive Summary

On March 20, 2026, CrowdStrike disclosed a supply chain compromise involving the popular `trivy-action` GitHub Action used in CI/CD pipelines. Attackers repointed Git tags to serve malicious code that executed a multi-stage credential theft operation, exfiltrating sensitive data via a typosquatted domain and fallback GitHub repositories. The compromise affected 76 of 77 release tags, highlighting the risks of mutable Git tags in CI/CD workflows. Organizations are urged to audit their GitHub Actions usage, update to clean versions, and monitor for suspicious activity using the provided detection searches.
```
