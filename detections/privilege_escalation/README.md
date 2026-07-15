# Privilege Escalation Detections

**MITRE ATT&CK Tactic:** [Privilege Escalation (TA0004)](https://attack.mitre.org/tactics/TA0004/)
**Kill Chain Phase:** Exploitation

Detections for techniques adversaries use to gain higher-level permissions, including exploitation of vulnerabilities in services and applications, abuse of elevated process tokens, and living-off-the-land privilege escalation chains.

---

## Detections

| Detection | MITRE Technique | Description |
|-----------|----------------|-------------|
| [Cisco SD-WAN CVE-2026-20245 CLI Tenant-Upload Injection](cisco_sdwan_cve_2026_20245_tenant_upload_cli_injection.md) | T1068, T1190, T1136, T1078, T1070 | CVE-2026-20245 (CVSS 7.8): authenticated SD-WAN CLI tenant-upload command injects OS commands as root via vconfd_script_upload_tenant_list.sh; troot UID 0 backdoor account creation; active exploitation disclosed by Mandiant June 24 2026 |
| [AD FS Local Privilege Escalation (CVE-2026-56155)](adfs_eop_local_privilege_escalation_cve_2026_56155.md) | T1068 | Insufficient granularity of access control in AD FS (CVSS 7.8) allows an authenticated local user to escalate to administrator; ADFS service spawning command interpreters or local admin group modifications are primary indicators; CISA KEV July 14 2026 |
| [Microsoft SharePoint Server CVE-2026-56164 Missing Auth EoP](sharepoint_cve_2026_56164_missing_auth_eop.md) | T1190, T1098, T1548, T1136 | CVE-2026-56164 (CWE-306): unauthenticated attacker calls privileged SharePoint REST endpoints without credentials to elevate to site admin; CISA KEV added 2026-07-14 with 3-day deadline |
| [Oracle EBS CVE-2026-46817 Payments Unauthenticated Privilege Escalation](oracle_ebs_cve_2026_46817_payments_privesc.md) | T1190, T1548, T1083, T1552.001 | CVE-2026-46817 (CVSS 9.8): unauthenticated POST to /OA_HTML/ibytransmit invokes internal Oracle Java function to read arbitrary server files; auth bypass on Oracle Payments File Transmission; CISA KEV added 2026-07-15 with July 18 deadline |

## Threat Actors

| Actor | Techniques | References |
|-------|-----------|-----------|
| Unattributed (state-sponsored suspected) | T1068, T1190, T1136 | [Mandiant GTIG — CVE-2026-20245 (June 2026)](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager) |
| Unknown (CVE-2026-56155 AD FS exploiters, July 2026) | T1068 | [CISA KEV (2026-07-14)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [Tenable — Microsoft July 2026 Patch Tuesday](https://www.tenable.com/blog/microsofts-july-2026-patch-tuesday-addresses-569-cves-cve-2026-56155-cve-2026-56164) |
| Multiple (CISA KEV confirmed exploitation) | T1190, T1098 | CVE-2026-56164 SharePoint Missing Auth EoP; attribution not yet disclosed |
| Unattributed (CVE-2026-46817 Oracle EBS exploiters, June–July 2026) | T1190, T1548, T1083 | [The Hacker News — CVE-2026-46817 (June 2026)](https://thehackernews.com/2026/06/oracle-e-business-suite-flaw-cve-2026.html), [CISA KEV (2026-07-15)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
