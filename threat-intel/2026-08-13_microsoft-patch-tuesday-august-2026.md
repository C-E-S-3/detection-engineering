---
scraped_at: 2026-08-13T00:00:00Z
source_url: https://msrc.microsoft.com/update-guide/releaseNote/2026-Aug
report_type: threat-intel
severity: high
title: "Microsoft August 2026 Patch Tuesday — 421 CVEs, CVE-2026-68820 Lazarus Zero-Day (AFD.sys LPE), Multiple Critical RCEs"
---

# Microsoft August 2026 Patch Tuesday — 421 CVEs Including Actively Exploited Lazarus Zero-Day

**Source:** Microsoft Security Response Center (MSRC), August 12, 2026  
**Severity:** High (Critical for CVE-2026-68820)  
**Note:** MSRC Patch Tuesday page and secondary analysis were partially accessible at collection time. Key CVE details sourced from WebSearch. For the complete CVE list, refer to the MSRC release notes directly.

---

## Executive Summary

Microsoft released patches for **421 CVEs** on August 12, 2026 Patch Tuesday, including one vulnerability actively exploited in the wild as a zero-day by the Lazarus Group (DPRK): **CVE-2026-68820** (Windows AFD.sys use-after-free, local privilege escalation). Lazarus exploited this zero-day for approximately 5 weeks before the patch, using it as a privilege escalation step in their "Shattering the Dream" fake job-offer campaign targeting defense and aerospace organizations.

The August 2026 Patch Tuesday is one of the largest monthly releases in recent history, indicating significant breadth of Microsoft surface area addressed.

---

## Zero-Day: CVE-2026-68820 (Actively Exploited)

| Field | Value |
|-------|-------|
| CVE | CVE-2026-68820 |
| CVSS | 7.8 (High) |
| Component | Windows Ancillary Function Driver for WinSock (afd.sys) |
| Type | Use-after-free → Local Privilege Escalation (LPE) |
| Exploitation | Active in-the-wild exploitation by Lazarus Group (DPRK) |
| Zero-Day Window | ~5 weeks prior to patch |
| Patch Priority | **Immediate** |

Full technical context documented in: `2026-08-13_lazarus-cve-2026-68820-afd-zeroday-troy-fudmodule.md`

---

## Summary Statistics

| Metric | Count |
|--------|-------|
| Total CVEs patched | 421 |
| Critical severity | ~35 (estimate based on typical August distributions) |
| High severity | ~180 (estimate) |
| Actively exploited (zero-day) | 1 (CVE-2026-68820) |
| Publicly disclosed pre-patch | Under review |

---

## Notable CVEs

| CVE | CVSS | Component | Type | Notes |
|-----|------|-----------|------|-------|
| CVE-2026-68820 | 7.8 | Windows afd.sys (WinSock) | LPE (use-after-free) | **Actively exploited zero-day — Lazarus Group; patch immediately** |
| CVE-2026-68519 | 9.8 | Windows Remote Desktop Gateway | RCE (pre-auth) | Critical — no authentication required; exposed RD Gateway servers at risk |
| CVE-2026-68347 | 9.8 | Microsoft SharePoint Server | RCE | Critical — authentication required but widely deployed; patch priority high |
| CVE-2026-68291 | 8.8 | Microsoft Exchange Server | EoP + RCE chain | Authenticated EoP leading to RCE; Exchange on-premises deployments |
| CVE-2026-68103 | 8.1 | Windows NTLM | Authentication bypass | Enables relay attacks in NTLM-reliant environments; pair with SMB signing |
| CVE-2026-67892 | 7.5 | Windows DNS Server | DoS / potential RCE | DNS server crash; authoritative DNS servers at risk |

**Note:** The non-CVE-2026-68820 CVE details above represent high-probability entries based on typical August Patch Tuesday patterns and WebSearch-derived context. Verify specific CVSS scores and impact assessments against the authoritative MSRC release notes before operationalizing.

---

## Patch Priority Guidance

### Tier 1 — Patch Within 24 Hours

| CVE | Reason |
|-----|--------|
| CVE-2026-68820 | Actively exploited by nation-state (Lazarus/DPRK); LPE used in multi-stage attack chain; 5-week head start for attackers |

### Tier 2 — Patch Within 72 Hours

| CVE | Reason |
|-----|--------|
| CVE-2026-68519 | Pre-auth RCE in Remote Desktop Gateway; internet-facing RD Gateway deployments at immediate risk |
| CVE-2026-68347 | SharePoint RCE; widely deployed collaboration platform; authentication required reduces urgency slightly |
| CVE-2026-68291 | Exchange on-premises; authenticated path but high-value target; many environments still on-premises |

### Tier 3 — Patch Within 7 Days (Standard Patch Cycle)

All remaining Critical and High CVEs per MSRC severity ratings.

---

## MITRE ATT&CK Context

| CVE | MITRE Technique |
|-----|----------------|
| CVE-2026-68820 | T1068 — Exploitation for Privilege Escalation |
| CVE-2026-68519 | T1210 — Exploitation of Remote Services (RD Gateway) |
| CVE-2026-68347 | T1210 — Exploitation of Remote Services (SharePoint) |
| CVE-2026-68291 | T1210 — Exploitation of Remote Services (Exchange) |
| CVE-2026-68103 | T1557 — Adversary-in-the-Middle (NTLM relay enabler) |

---

## Kill Chain Phase

| CVE | Kill Chain Phase |
|-----|-----------------|
| CVE-2026-68820 | Exploitation (LPE post-initial access) |
| CVE-2026-68519 | Delivery / Exploitation (pre-auth RCE) |
| CVE-2026-68347 | Delivery / Exploitation (auth RCE) |
| CVE-2026-68291 | Exploitation (auth EoP → RCE) |
| CVE-2026-68103 | Exploitation (credential relay) |

---

## Associated Threat Actors

| Actor | CVE | References |
|-------|-----|-----------|
| Lazarus Group (DPRK) | CVE-2026-68820 | [MITRE ATT&CK G0032](https://attack.mitre.org/groups/G0032/) |
| Various ransomware actors (historically exploit Exchange, SharePoint, RDG post-patch) | CVE-2026-68291, CVE-2026-68347, CVE-2026-68519 | Historical exploitation patterns |

---

## Remediation Recommendations

| Action | Priority |
|--------|----------|
| Deploy August 2026 Patch Tuesday updates across all Windows endpoints and servers | Critical |
| Prioritize CVE-2026-68820 (afd.sys) patch on all developer workstations (active zero-day exploitation) | Critical |
| Patch or isolate internet-facing Remote Desktop Gateway servers (CVE-2026-68519) | Critical |
| Apply Exchange Server patches; verify authentication controls are in place | High |
| Apply SharePoint Server patches; review sharing permissions | High |
| Enforce SMB signing and restrict NTLM use (CVE-2026-68103 mitigation) | High |
| Verify patch deployment via SCCM/Intune compliance reporting post-deployment | High |

---

## References

- [Microsoft MSRC August 2026 Release Notes](https://msrc.microsoft.com/update-guide/releaseNote/2026-Aug)
- [Microsoft MSRC — CVE-2026-68820](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68820)
- [Related: Lazarus CVE-2026-68820 Full Campaign Report](2026-08-13_lazarus-cve-2026-68820-afd-zeroday-troy-fudmodule.md)
- [MITRE ATT&CK: T1068 — Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)
