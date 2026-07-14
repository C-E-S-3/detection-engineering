# Privilege Escalation Detections

**MITRE ATT&CK Tactic:** [Privilege Escalation (TA0004)](https://attack.mitre.org/tactics/TA0004/)
**Kill Chain Phase:** Exploitation

Detections for techniques adversaries use to gain higher-level permissions, including exploitation of vulnerabilities in services and applications, abuse of elevated process tokens, and living-off-the-land privilege escalation chains.

---

## Detections

| Detection | MITRE Technique | Description |
|-----------|----------------|-------------|
| [Cisco SD-WAN CVE-2026-20245 CLI Tenant-Upload Injection](cisco_sdwan_cve_2026_20245_tenant_upload_cli_injection.md) | T1068, T1190, T1136, T1078, T1070 | CVE-2026-20245 (CVSS 7.8): authenticated SD-WAN CLI tenant-upload command injects OS commands as root via vconfd_script_upload_tenant_list.sh; troot UID 0 backdoor account creation; active exploitation disclosed by Mandiant June 24 2026 |
| [Microsoft ADFS CVE-2026-56155 Insufficient Access Control EoP](adfs_cve_2026_56155_access_control_eop.md) | T1068, T1484.002, T1078.002, T1550.001, T1059.001 | CVE-2026-56155 (CWE-1220): authorized attacker abuses ADFS access control granularity flaw to obtain tokens for unauthorized relying parties or modify RPT/claims configuration to elevate privileges; CISA KEV added 2026-07-14 |

## Threat Actors

| Actor | Techniques | References |
|-------|-----------|-----------|
| Unattributed (state-sponsored suspected) | T1068, T1190, T1136 | [Mandiant GTIG — CVE-2026-20245 (June 2026)](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager) |
| COZY BEAR / APT29 | T1550.001, T1484.002 | [MITRE ATT&CK G0016](https://attack.mitre.org/groups/G0016/) — known ADFS targeting for Golden SAML and federated identity attacks |
| SCATTERED SPIDER / Octo Tempest | T1484.002, T1078.002 | [MITRE ATT&CK G1015](https://attack.mitre.org/groups/G1015/) — active targeting of federated identity infrastructure |
