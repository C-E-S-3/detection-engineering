---
scraped_at: 2026-07-15T00:00:00Z
source_url: https://www.tenable.com/blog/microsofts-july-2026-patch-tuesday-addresses-569-cves-cve-2026-56155-cve-2026-56164
report_type: threat-intel
severity: high
title: "Microsoft July 2026 Patch Tuesday — CVE-2026-56155 (AD FS EoP) and CVE-2026-56164 (SharePoint Missing Auth) Actively Exploited"
---

## 1. IOCs

No confirmed network IOCs (threat actor infrastructure not publicly attributed at time of reporting).

---

## 2. Summary

Microsoft's July 2026 Patch Tuesday (released July 14, 2026) addresses 569 CVEs, including two actively exploited zero-days that were simultaneously added to the CISA KEV catalog. Both vulnerabilities were exploited in the wild prior to patch availability.

---

## 3. Key Vulnerabilities

### CVE-2026-56155 — AD FS Elevation of Privilege (Actively Exploited)

| Field | Value |
|-------|-------|
| CVSS | 7.8 |
| Attack Vector | Local |
| Attack Complexity | Low |
| Privileges Required | Low |
| User Interaction | None |
| CWE | Insufficient Granularity of Access Control |

An authenticated local user on an Active Directory Federation Services server can exploit insufficient access control granularity to escalate privileges to administrative level. The local attack vector means an adversary must already have a foothold on the ADFS server (e.g., via phishing, RDP credential theft, or prior exploitation of an adjacent vulnerability) before this can be exploited. Post-exploitation impact includes full control of the ADFS service, enabling forged authentication tokens, SSO bypass, and lateral movement across federated identity infrastructure.

### CVE-2026-56164 — SharePoint Server Elevation of Privilege (Actively Exploited)

| Field | Value |
|-------|-------|
| CVSS | 5.3 |
| Attack Vector | Network |
| Attack Complexity | Low |
| Privileges Required | None |
| User Interaction | None |
| CWE | Missing Authentication for Critical Function |

An unauthenticated network-adjacent attacker can access a critical SharePoint Server function without any credentials or user interaction. Affects SharePoint Server 2016, 2019, and Subscription Edition. Despite the relatively lower CVSS score, the complete absence of authentication requirements and network accessibility make this high-priority for any internet-exposed SharePoint deployment. CISA KEV addition confirms in-the-wild exploitation.

### CVE-2026-50661 — BitLocker Security Feature Bypass (Publicly Disclosed)

| Field | Value |
|-------|-------|
| Attack Vector | Physical |
| Note | Publicly disclosed but requires physical access; lower exploitation urgency |

---

## 4. Affected Products

| CVE | Affected Products |
|-----|------------------|
| CVE-2026-56155 | Windows Server 2019, 2022, 2025 running AD FS role |
| CVE-2026-56164 | SharePoint Server 2016, SharePoint Server 2019, SharePoint Server Subscription Edition |
| CVE-2026-50661 | Windows 10/11, Windows Server 2016+ with BitLocker enabled |

---

## 5. MITRE ATT&CK

| CVE | Tactic | Tactic ID | Technique | Technique ID |
|-----|--------|-----------|-----------|-------------|
| CVE-2026-56155 | Privilege Escalation | TA0004 | Exploitation for Privilege Escalation | T1068 |
| CVE-2026-56164 | Initial Access | TA0001 | Exploit Public-Facing Application | T1190 |

---

## 6. Kill Chain Phase

- CVE-2026-56155: Exploitation (post-initial-access privilege escalation)
- CVE-2026-56164: Delivery → Exploitation

---

## 7. Remediation

- Apply July 2026 Patch Tuesday updates immediately; CISA BOD 22-01 requires FCEB agencies to patch CVE-2026-56155 and CVE-2026-56164 within the specified deadline.
- For CVE-2026-56164 (SharePoint): restrict network access to SharePoint to authenticated users at the reverse proxy/WAF layer pending patching; audit IIS logs for unauthenticated POST requests.
- For CVE-2026-56155 (AD FS): audit ADFS servers for unexpected local accounts or group membership changes; ensure ADFS servers are on an isolated admin network with no direct internet access.
- Review ADFS token issuance logs for anomalous claims or unusual federated authentication events.

---

## 8. References

- [Tenable — Microsoft July 2026 Patch Tuesday (2026-07-14)](https://www.tenable.com/blog/microsofts-july-2026-patch-tuesday-addresses-569-cves-cve-2026-56155-cve-2026-56164)
- [CISA KEV — CVE-2026-56155](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [CISA KEV — CVE-2026-56164](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Microsoft Security Update Guide — July 2026](https://msrc.microsoft.com/update-guide/)
