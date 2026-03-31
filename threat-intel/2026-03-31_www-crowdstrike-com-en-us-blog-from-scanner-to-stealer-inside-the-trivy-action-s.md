---
scraped_at: 2026-03-20T00:00:00Z
source_url: https://www.crowdstrike.com/en-us/blog/from-scanner-to-stealer-inside-the-trivy-action-supply-chain-compromise/
report_type: threat-intel
---

## 1. Indicators of Compromise (IOCs)

### IP Addresses
- None identified in the source.

### Domains/URLs
- `scan.aquasecurtiy[.]org`: Typosquatted domain used for HTTPS exfiltration.
- `hxxps[://]tdtqy-oyaaa-aaaae-af2dq-cai[.]raw[.]icp0[.]io`: C2 server hosted on the Internet Computer (ICP) blockchain.

### File Hashes
- `18a24f83e807479438dcab7a1804c51a00dafc1d526698a66e0640d1e5dd671a`: SHA256 hash of compromised `entrypoint.sh` in `aquasecurity/trivy-action` tag 0.24.0.
- `07500e81693c06ef7ac6bf210cff9c882bcc11db5f16b5bded161218353ba4da`: SHA256 hash of legitimate `entrypoint.sh` in `aquasecurity/trivy-action` tag 0.35.0.

### Email Addresses
- None identified in the source.

### File Names/Paths
- `/home/runner/_work/_temp/395479a1-…ded349.sh`: Temporary script executed during the attack.
- `~/.config/sysmon.py`: Malicious loader script dropped by compromised `trivy` scanner version 0.69.4.
- `/tmp/pglog`: Filename used for downloaded malicious binaries.

### Registry Keys
- None identified in the source.

### Mutex Names
- None identified in the source.

### C2 Infrastructure
- `scan.aquasecurtiy[.]org`: Primary exfiltration domain.
- `hxxps[://]tdtqy-oyaaa-aaaae-af2dq-cai[.]raw[.]icp0[.]io`: ICP-hosted C2 server.

## 2. TTPs (MITRE ATT&CK Mapping)

### Tactics and Techniques
- **T1071.001 - Application Layer Protocol: Web Protocols**: Exfiltration of data via HTTPS POST requests to `scan.aquasecurtiy[.]org`.
- **T1560.001 - Archive Collected Data: Archive via Utility**: Data encrypted and packaged as `tpcp.tar.gz`.
- **T1027 - Obfuscated Files or Information**: Use of Base64-encoded Python scripts and encrypted payloads.
- **T1005 - Data from Local System**: Credential harvesting from local filesystems (e.g., SSH keys, cloud credentials).
- **T1552.001 - Unsecured Credentials: Credentials in Files**: Targeting `.env` files and other credential storage locations.
- **T1552.003 - Unsecured Credentials: Credentials in Memory**: Scraping memory for GitHub Actions secrets.
- **T1567.002 - Exfiltration Over Web Service: Exfiltration to Code Repository**: Secondary exfiltration via public GitHub repositories.
- **T1573.001 - Encrypted Channel: Symmetric Cryptography**: AES-256-CBC encryption for exfiltrated data.
- **T1564.001 - Hide Artifacts: Hidden Files and Directories**: Use of dot-prefixed files for stealth.

## 3. Malware & Tools

### Malware Families
- **Compromised Trivy Scanner**: Versions 0.0.1 through 0.34.2 of `aquasecurity/trivy-action` were retroactively poisoned.
- **Sysmon.py Loader**: Lightweight stage-1 loader dropped by compromised `trivy` scanner version 0.69.4.

### Tools
- **Git**: Exploited for tag repointing to inject malicious code into `aquasecurity/trivy-action` releases.

## 4. Threat Actor / Campaign Attribution

- **Threat Actor**: Unnamed adversary leveraging supply chain attacks.
- **Campaign**: Compromise of `aquasecurity/trivy-action` GitHub Action and `trivy` scanner.
- **Motivations**: Credential theft and potential access to CI/CD pipelines and sensitive infrastructure.
- **Targeted Sectors**: Likely organizations using GitHub Actions for CI/CD pipelines, including open-source and enterprise environments.

## 5. Splunk Detection Searches

### Detecting Malicious Domains in Network Traffic
```spl
index=network sourcetype=stream:http OR sourcetype=bro_http
| search uri="scan.aquasecurtiy.org" OR uri="tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io"
| stats count by src_ip, dest_ip, uri, http_user_agent
```

### Detecting Malicious File Hashes
```spl
index=endpoint sourcetype=Endpoint:File
| search file_hash="18a24f83e807479438dcab7a1804c51a00dafc1d526698a66e0640d1e5dd671a" OR file_hash="07500e81693c06ef7ac6bf210cff9c882bcc11db5f16b5bded161218353ba4da"
| stats count by file_name, file_path, file_hash
```

### Detecting Suspicious Temporary Scripts
```spl
index=endpoint sourcetype=XmlWinEventLog OR sourcetype=linux_audit
| search file_path="/home/runner/_work/_temp/*.sh" OR file_path="~/.config/sysmon.py" OR file_path="/tmp/pglog"
| stats count by file_name, file_path, process_name
```

### Detecting Credential Harvesting Behavior
```spl
index=endpoint sourcetype=XmlWinEventLog OR sourcetype=linux_audit
| search process="python" AND (file_path="/proc/*/maps" OR file_path="/proc/*/mem")
| stats count by process_name, file_path, user
```

### Detecting Exfiltration via Public GitHub Repositories
```spl
index=github sourcetype=github:logs
| search event.action="release.create" AND repository.name="tpcp-docs"
| stats count by actor, repository.name, event.action
```

## 6. Executive Summary

On March 20, 2026, CrowdStrike identified a sophisticated supply chain attack targeting the `aquasecurity/trivy-action` GitHub Action and the `trivy` vulnerability scanner. The attack involved retroactive poisoning of Git tags to inject credential-stealing malware into CI/CD pipelines. The malware exfiltrates sensitive data via HTTPS and GitHub repositories, leveraging encrypted channels and stealth techniques. Organizations using affected versions of `trivy-action` or `trivy` are urged to update to clean versions immediately and audit their CI/CD workflows for exposure. Immediate actions include blocking malicious domains, scanning for compromised file hashes, and monitoring for suspicious runner activity.