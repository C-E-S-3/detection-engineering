---
scraped_at: "2026-03-31T17:45:14-04:00"
source_url: "https://www.bleepingcomputer.com/news/security/claude-ai-finds-vim-emacs-rce-bugs-that-trigger-on-file-open/"
report_type: threat-intel
---

## 1. Indicators of Compromise (IOCs)

### File Names/Paths
- `*.vim` files with malicious modelines (Vim RCE vulnerability)
- `.git/config` files containing malicious `core.fsmonitor` entries (GNU Emacs RCE vulnerability)

### Context
- Specially crafted files can exploit vulnerabilities in Vim and GNU Emacs to execute arbitrary code upon opening.

## 2. TTPs (MITRE ATT&CK Mapping)

### Tactic: Execution
- **Technique ID:** T1203
  **Technique Name:** Exploitation for Client Execution
  **Description:** The vulnerabilities in Vim and GNU Emacs allow attackers to execute arbitrary code by crafting malicious files that exploit the software's handling of modelines and Git configuration files.

### Tactic: Persistence
- **Technique ID:** T1547.001
  **Technique Name:** Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
  **Description:** Attackers can use the `.git/config` file to execute a malicious script via the `core.fsmonitor` option when the file is opened in GNU Emacs.

## 3. Malware & Tools

### Tools
- **Claude AI**: Used to identify and refine proof-of-concept exploits for the vulnerabilities in Vim and GNU Emacs.

## 4. Threat Actor / Campaign Attribution

### Attribution
- **Researcher:** Hung Nguyen, cybersecurity researcher at Calif, a boutique cybersecurity firm specializing in AI red teaming and security engineering.

### Campaign
- No specific campaign identified. The vulnerabilities were discovered as part of research activities.

## 5. Splunk Detection Searches

### Detecting Malicious Vim Modelines
```spl
index=main sourcetype=filesystem
| search file_name="*.vim"
| search file_content="modeline"
| table _time, host, file_name, file_path, file_content
```
*# This search identifies `.vim` files containing modelines, which could potentially exploit the Vim RCE vulnerability.*

### Detecting Malicious `.git/config` Files
```spl
index=main sourcetype=filesystem
| search file_name="config" file_path="*/.git/config"
| regex file_content="core\.fsmonitor.*"
| table _time, host, file_name, file_path, file_content
```
*# This search identifies `.git/config` files with potentially malicious `core.fsmonitor` entries.*

### Monitoring Git Operations Triggered by GNU Emacs
```spl
index=main sourcetype=process
| search process_name="git" parent_process_name="emacs"
| table _time, host, process_name, parent_process_name, process_command_line
```
*# This search monitors Git operations triggered by GNU Emacs, which could indicate exploitation of the RCE vulnerability.*

## 6. Executive Summary

Vulnerabilities in the Vim and GNU Emacs text editors have been discovered, allowing remote code execution (RCE) simply by opening a specially crafted file. The Vim vulnerability, affecting versions 9.2.0271 and earlier, has been patched in version 9.2.0272. However, the GNU Emacs vulnerability remains unpatched, as its maintainers argue that it is a Git issue. Users are advised to update Vim to the latest version and exercise caution when opening files from untrusted sources. Organizations should implement detection mechanisms for malicious Vim modelines and `.git/config` files to mitigate potential exploitation.