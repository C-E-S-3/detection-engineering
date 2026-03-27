---
scraped_at: "2026-03-27T16:51:52Z"
source_url: "https://www.bleepingcomputer.com/news/security/fake-vs-code-alerts-on-github-spread-malware-to-developers/"
report_type: threat-intel
---

## 1. Indicators of Compromise (IOCs)

### Domains
- `drnatashachinn[.]com` - Used as part of a cookie-driven redirection chain to execute a JavaScript reconnaissance script.

### URLs
- Links to malicious files hosted on Google Drive (specific URLs not provided in the source).

### File Hashes
- No specific file hashes were provided in the source.

### IP Addresses
- No specific IP addresses were provided in the source.

### Other IOCs
- None identified.

## 2. TTPs (MITRE ATT&CK Mapping)

### Tactics and Techniques
- **T1566.002 - Phishing: Spearphishing Link**: Threat actors post fake Visual Studio Code (VS Code) security alerts in GitHub Discussions sections to trick developers into downloading malware.
- **T1204.001 - User Execution: Malicious Link**: Links in the fake alerts redirect victims to malicious domains and initiate a cookie-driven redirection chain.
- **T1592.001 - Gather Victim Host Information: Hardware**: JavaScript reconnaissance script collects details such as timezone, locale, user agent, OS details, and automation indicators.
- **T1071.001 - Application Layer Protocol: Web Protocols**: The reconnaissance data is sent to the command-and-control server via a POST request.
- **T1074.001 - Data Staged: Local Data Staging**: The reconnaissance script packages victim data before sending it to the C2 server.

## 3. Malware & Tools
- **Reconnaissance JavaScript Payload**: Collects victim metadata (e.g., timezone, locale, OS details) and filters out bots and researchers.
- **Traffic Distribution System (TDS)**: Used to profile targets and deliver second-stage payloads selectively.

## 4. Threat Actor / Campaign Attribution
- **Threat Actor**: Unnamed, but described as part of a well-organized, large-scale operation.
- **Campaign**: Large-scale phishing campaign targeting GitHub developers with fake VS Code security alerts.
- **Motivation**: Likely data collection and potential further exploitation of developers.
- **Targeted Sectors**: Developers using GitHub, specifically those working with Visual Studio Code extensions.

## 5. Splunk Detection Searches

### Detecting Access to Malicious Domain
```spl
index=proxy OR index=web
| search dest="drnatashachinn.com"
| stats count by src_ip, dest, uri_path, http_method
| table src_ip, dest, uri_path, http_method, count
```

### Detecting Google Drive Links in GitHub Discussions
```spl
index=web OR index=proxy
| search uri="*.google.com/*"
| regex uri_path="(?i)(.*\.drive\.google\.com.*)"
| stats count by src_ip, uri, http_method
| table src_ip, uri, http_method, count
```

### Detecting Reconnaissance JavaScript Payload
```spl
index=web OR index=proxy
| search "POST" AND "drnatashachinn.com"
| stats count by src_ip, dest, uri_path, http_method, user_agent
| table src_ip, dest, uri_path, http_method, user_agent, count
```

### Behavioral Detection for Mass GitHub Notifications
```spl
index=email
| search subject="Severe Vulnerability - Immediate Update Required"
| stats count by recipient, sender, subject
| where count > 10
| table recipient, sender, subject, count
```

## 6. Executive Summary
A large-scale phishing campaign is targeting developers on GitHub by posting fake Visual Studio Code (VS Code) security alerts in the Discussions sections of repositories. These alerts, crafted to appear legitimate, include links to malicious files hosted on Google Drive. Clicking these links redirects victims to a malicious domain (`drnatashachinn[.]com`) that executes a JavaScript reconnaissance script to collect victim metadata and filter out bots and researchers. The campaign appears to be well-organized and automated, targeting developers to potentially compromise their systems or steal sensitive information. Immediate actions include blocking the identified domain, monitoring for suspicious GitHub notifications, and educating users on verifying the legitimacy of security alerts.