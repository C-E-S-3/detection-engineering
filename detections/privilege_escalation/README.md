# Privilege Escalation Detections

**MITRE ATT&CK Tactic:** [Privilege Escalation (TA0004)](https://attack.mitre.org/tactics/TA0004/)
**Kill Chain Phase:** Exploitation

Detections for techniques adversaries use to gain higher-level permissions, including exploitation of vulnerabilities in services and applications, abuse of elevated process tokens, and living-off-the-land privilege escalation chains.

---

## Detections

| Detection | MITRE Technique | Description |
|-----------|----------------|-------------|
| [Cisco SD-WAN CVE-2026-20245 CLI Tenant-Upload Injection](cisco_sdwan_cve_2026_20245_tenant_upload_cli_injection.md) | T1068, T1190, T1136, T1078, T1070 | CVE-2026-20245 (CVSS 7.8): authenticated SD-WAN CLI tenant-upload command injects OS commands as root via vconfd_script_upload_tenant_list.sh; troot UID 0 backdoor account creation; active exploitation disclosed by Mandiant June 24 2026 |

## Threat Actors

| Actor | Techniques | References |
|-------|-----------|-----------|
| Unattributed (state-sponsored suspected) | T1068, T1190, T1136 | [Mandiant GTIG — CVE-2026-20245 (June 2026)](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager) |
