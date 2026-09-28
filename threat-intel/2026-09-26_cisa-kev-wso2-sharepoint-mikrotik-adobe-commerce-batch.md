---
scraped_at: 2026-09-26T18:00:00Z
source_url: https://www.bleepingcomputer.com/news/security/cisa-warns-of-sharepoint-wso2-adobe-commerce-flaws-exploited-in-attacks/
report_type: threat-intel
severity: high
title: "CISA KEV September 26, 2026: WSO2 JWT Auth Bypass (CVSS 10.0), SharePoint Code Injection, MikroTik SSH Bypass, Adobe Commerce Auth Flaw"
---

# CISA KEV September 26, 2026: WSO2 JWT Auth Bypass (CVSS 10.0), SharePoint Code Injection, MikroTik SSH Bypass, Adobe Commerce Auth Flaw

## 1. IOCs

### Domains / Infrastructure
No specific threat-actor-controlled domains or IPs published for this KEV batch.

### Indicators of Exploitation (WSO2 CVE-2026-5430)
watchTowr honeypots recorded exploitation attempts against WSO2 API Manager beginning September 13, 2026 — two weeks before CISA KEV addition. Specific attacker IPs have not been published.

- HTTP requests with JWT tokens signed using unsupported/weak algorithms (`none`, `HS256` with public key material, algorithm confusion)
- Requests to WSO2 admin APIs (`/api/am/admin/`, `/api/am/publisher/`) without valid credentials
- User agent strings associated with security tooling (`wso2-scanner`, `nuclei`, `wget`, `python-requests`)

## 2. TTPs

| CVE | CVSS | Tactic | Technique ID | Technique | Details |
|-----|------|--------|-------------|-----------|---------|
| CVE-2026-5430 | 10.0 Critical | Initial Access TA0001 | T1190 | Exploit Public-Facing Application | WSO2 API Manager JWT authentication bypass — forged token signed with unsupported algorithm bypasses all auth checks; grants full admin access |
| CVE-2026-5430 | 10.0 Critical | Defense Evasion TA0005 | T1550.001 | Use Alternate Authentication Material: Application Access Token | Attacker-controlled JWT used as valid session token |
| CVE-2026-65660 | High | Initial Access TA0001 | T1190 | Exploit Public-Facing Application | Microsoft SharePoint code injection; CVSS not yet published; allows RCE under SharePoint service account |
| CVE-2026-67279 | Medium | Initial Access TA0001 | T1190 | Exploit Public-Facing Application | MikroTik RouterOS pre-authentication SSH state-machine/workflow bypass |
| CVE-2026-71362 | High | Initial Access TA0001 | T1190 | Exploit Public-Facing Application | Adobe Commerce/Magento incorrect authorization flaw actively exploited to hijack merchant customer accounts |

## 3. Malware & Tools

No specific malware families attributed to this KEV batch. CVE-2026-5430 (WSO2) is consistent with:
- Initial access brokers exploiting API management platforms
- Ransomware affiliate pre-compromise tooling
- Nation-state actors targeting API gateways for persistence and lateral movement

## 4. Threat Actor / Campaign Attribution

None publicly attributed. watchTowr's honeypot data indicates CVE-2026-5430 exploitation began September 13, 2026. The CVE affects organizations using WSO2 API management products broadly in enterprise environments.

### Vulnerability Details

| CVE | Product(s) | Affected Versions | Fixed In | Federal Deadline | Severity |
|-----|-----------|-------------------|---------|-----------------|---------|
| CVE-2026-5430 | WSO2 API Manager, API Control Plane, Traffic Manager, Universal Gateway | 4.1.0–4.6.0 (API Manager/Control Plane); 4.5.0–4.6.0 (Traffic Manager/Universal Gateway) | See WSO2-2026-5328 advisory | September 27, 2026 | CVSS 10.0 Critical |
| CVE-2026-71362 | Adobe Commerce, Magento | Multiple versions | Adobe Security Bulletin | September 27, 2026 | High |
| CVE-2026-65660 | Microsoft SharePoint | Multiple versions | Microsoft Patch Tuesday or OOB update | September 28, 2026 | High |
| CVE-2026-67279 | MikroTik RouterOS | Multiple branches | RouterOS updates | September 28, 2026 | Medium |

**Note:** CVE-2026-67279 (MikroTik RouterOS) is distinct from CVE-2026-67277, which was tracked in `2026-09-11_cert-pl-helpnetsecurity-mikrotrick-mikrotik-routeros-cve-2026-67277-cve-2026-86060.md`.

## 5. Splunk Detection Searches

### Detect Suspicious WSO2 API Admin Requests (CVE-2026-5430)
```spl
`o365`
  (uri="/api/am/admin/*" OR uri="/api/am/publisher/*" OR uri="/carbon/admin/*")
  (status IN (200,201,301,302) OR http_method="POST")
| eval jwt_alg=if(match(coalesce(http_user_agent,"-"), "(?i)none|algorithm.?confusion"), "suspicious", "normal")
| where jwt_alg="suspicious" OR (NOT match(src_ip, "^10\.|^172\.16\.|^192\.168\."))
| eval risk_score=case(
    uri="/api/am/admin/*" AND NOT match(src_ip,"^10\.|^172\.16\.|^192\.168\."), 90,
    uri="/api/am/publisher/*", 75,
    1=1, 60)
| where risk_score >= 60
| table _time src_ip uri http_method status http_user_agent jwt_alg risk_score
```

### Detect WSO2 API Manager JWT Auth Bypass Pattern in Web Logs
```spl
`web`
  (uri_path IN ("/api/am/admin*","/api/am/publisher*","/api/am/store*","/carbon/admin*"))
  status IN (200,201)
| rex field=cs_uri_query "(?i)(?P<auth_header>Authorization\s*[:=]\s*Bearer\s+[^\s&]+)"
| eval b64_header=mvindex(split(auth_header,"."),0)
| where len(auth_header) > 0
| eval risk_score=85
| table _time src dest uri_path status auth_header risk_score
```

### Detect MikroTik RouterOS Pre-Auth SSH Traffic Anomalies (CVE-2026-67279)
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_port=22
    AND (All_Traffic.app="ssh" OR All_Traffic.app="unknown")
  by All_Traffic.src All_Traffic.src_ip All_Traffic.dest All_Traffic.dest_ip
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eventstats dc(src_ip) as distinct_sources by dest_ip
| where distinct_sources > 20
| eval risk_score=case(distinct_sources > 100, 85, distinct_sources > 20, 70, 1=1, 50)
| where risk_score >= 70
| table firstTime lastTime dest_ip distinct_sources count risk_score
```

### Detect Adobe Commerce Admin Privilege Escalation
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Web.Web
  where Web.uri_path IN ("/admin*","/index.php/admin*")
    AND Web.http_method="POST"
    AND Web.status IN (200,301,302)
  by Web.src Web.dest Web.uri_path Web.http_user_agent Web.status Web.bytes_out
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(uri_path,"admin.*account"), 80,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime src dest uri_path http_user_agent status bytes_out risk_score
```

## 6. Executive Summary

CISA added four actively exploited vulnerabilities to the KEV catalog on September 25–26, 2026, with federal agency patch deadlines of September 27–28. The highest priority is CVE-2026-5430 in WSO2 API Manager: a CVSS 10.0 JWT authentication bypass that has been exploited since at least September 13, allows unauthenticated full administrative access, and affects the widely deployed WSO2 API management stack (API Manager, Control Plane, Traffic Manager, Universal Gateway versions 4.1.0–4.6.0). CVE-2026-65660 (SharePoint code injection) and CVE-2026-71362 (Adobe Commerce authorization bypass) are also High severity with active exploitation observed. CVE-2026-67279 (MikroTik RouterOS SSH pre-auth bypass) is Medium severity but affects widely deployed network infrastructure. Organizations running any of these products should prioritize patching immediately and audit web access logs for anomalous admin-path requests.

## References

- [BleepingComputer: CISA warns of Sharepoint, WSO2, Adobe Commerce flaws exploited in attacks](https://www.bleepingcomputer.com/news/security/cisa-warns-of-sharepoint-wso2-adobe-commerce-flaws-exploited-in-attacks/)
- [The Hacker News: WSO2 and Adobe Commerce Flaws Exploited in Attacks, Added to CISA KEV](https://thehackernews.com/2026/09/wso2-and-adobe-commerce-flaws-exploited.html)
- [WSO2 Security Advisory WSO2-2026-5328](https://security.docs.wso2.com/en/latest/security-announcements/security-advisories/2026/WSO2-2026-5328/)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Microsoft SharePoint CVE-2026-65660 Security Update](https://msrc.microsoft.com/)
- [Adobe Commerce Security Bulletin](https://helpx.adobe.com/security/products/magento.html)
- [MikroTik RouterOS Security](https://mikrotik.com/security)
