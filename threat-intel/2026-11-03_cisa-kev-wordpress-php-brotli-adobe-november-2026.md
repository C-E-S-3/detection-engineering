---
scraped_at: 2026-11-04T00:00:00Z
source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
report_type: threat-intel
severity: critical
title: "CISA KEV: WordPress, PHP, Brotli, Adobe Commerce — November 2026 Additions"
---

# CISA KEV: WordPress, PHP, Brotli, Adobe Commerce — November 2026 Additions

**Source:** CISA Known Exploited Vulnerabilities Catalog  
**Published:** 2026-11-03  
**Severity:** Critical

---

## 1. IOCs

No network IOCs (domains, IPs, hashes) published with these CVE additions. Detection relies on web application logs and patch verification.

### CVEs Added to KEV — 2026-11-03

| CVE | Vendor / Product | CVSS | CISA Action Due | Description |
|-----|-----------------|------|-----------------|-------------|
| CVE-2026-119977 | WordPress Core | 8.1 | 2026-11-24 | Unauthenticated RCE via race condition in comment/post processing; affects WordPress < 6.9.3 |
| CVE-2026-109618 | PHP (8.x) | 9.8 | 2026-11-24 | Unauthenticated RCE in PHP-FPM FastCGI process manager; affects PHP 8.0–8.3 prior to respective patch versions |
| CVE-2026-109619 | PHP (8.x) | 9.8 | 2026-11-24 | Related unauthenticated RCE in PHP-FPM; companion to CVE-2026-109618; same affected versions |
| CVE-2026-111497 | Google Brotli (libbrotli) | 9.8 | 2026-11-10 | Heap buffer overflow in Brotli decompression library; exploitable via malicious compressed content in web servers, CDNs, and apps embedding libbrotli |
| CVE-2026-48356 | Adobe Commerce / Magento | 9.1 | 2026-11-10 | Unauthenticated RCE via Magento Admin API; exploited in targeted campaigns against e-commerce platforms |

---

## 2. TTPs (MITRE ATT&CK)

| CVE | Tactic | Technique | Notes |
|-----|--------|-----------|-------|
| CVE-2026-119977 | TA0001 Initial Access | T1190 — Exploit Public-Facing Application | WordPress sites without 6.9.3+ patch |
| CVE-2026-109618/19 | TA0001 Initial Access | T1190 — Exploit Public-Facing Application | PHP-FPM servers; nginx+PHP common stack |
| CVE-2026-111497 | TA0001 Initial Access | T1190 — Exploit Public-Facing Application | Via compressed HTTP request to any app using libbrotli |
| CVE-2026-48356 | TA0001 Initial Access | T1190 — Exploit Public-Facing Application | Magento e-commerce admin API |
| All | TA0003 Persistence | T1505.003 — Server-Side Webshell | Follow-on webshell deployment after initial RCE is standard pattern |

---

## 3. Malware & Tools

No specific malware families attributed at time of KEV publication. Historical exploitation of similar WordPress and PHP-FPM vulnerabilities has been associated with webshell deployment (PHP webshells, JSP shells on adjacent services) and cryptominer installation.

---

## 4. Threat Actor / Campaign Attribution

CISA KEV additions indicate active exploitation in the wild. No specific threat actor attribution published. The PHP-FPM and WordPress vulnerabilities (high CVSS, broad install base) are typical targets for opportunistic mass-exploitation campaigns.

---

## 5. Splunk Detection Searches

### 5.1 WordPress Exploitation Attempt (CVE-2026-119977)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Web.Web
  where (Web.uri_path="*/wp-comments-post.php*" OR Web.uri_path="*/xmlrpc.php*")
    AND Web.http_method="POST"
    AND Web.status IN (200, 500, 503)
  by Web.src Web.dest Web.uri_path Web.user_agent Web.http_method Web.status
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=65
| where risk_score >= 50
| table firstTime lastTime src dest uri_path user_agent http_method status risk_score
```

### 5.2 PHP-FPM Anomalous FastCGI Request (CVE-2026-109618/19)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Web.Web
  where Web.uri_path="*.php*"
    AND Web.http_content_type="*application/x-www-form-urlencoded*"
    AND Web.status=200
    AND Web.bytes_in > 50000
  by Web.src Web.dest Web.uri_path Web.user_agent Web.bytes_in
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=60
| where risk_score >= 50
| table firstTime lastTime src dest uri_path user_agent bytes_in risk_score
```

### 5.3 Adobe Commerce / Magento Admin API Exploitation (CVE-2026-48356)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Web.Web
  where Web.uri_path="*/rest/*/V1/*" OR Web.uri_path="*/api/rest*"
    AND Web.http_method IN ("POST", "PUT")
    AND Web.status IN (200, 201)
  by Web.src Web.dest Web.uri_path Web.user_agent Web.http_method Web.status
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=70
| where risk_score >= 50
| table firstTime lastTime src dest uri_path user_agent http_method status risk_score
```

### 5.4 Post-Exploitation Webshell Access After PHP/WordPress RCE

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Web.Web
  where (Web.uri_path="*.php" AND Web.http_method="POST")
    AND (Web.bytes_out > 1000 OR Web.status=200)
  by Web.src Web.dest Web.uri_path Web.user_agent Web.status Web.bytes_out
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| where NOT (uri_path="*/wp-login.php" OR uri_path="*/wp-admin/*"
             OR uri_path="*/wp-cron.php")
| eval risk_score=65
| where risk_score >= 50
| table firstTime lastTime src dest uri_path user_agent status bytes_out risk_score
```

---

## 6. Executive Summary

CISA added five CVEs to the Known Exploited Vulnerabilities catalog on 2026-11-03, all indicating active in-the-wild exploitation. Two PHP-FPM RCEs (CVE-2026-109618 and CVE-2026-109619) with CVSS 9.8, and a WordPress core race-condition RCE (CVE-2026-119977), are due for remediation by November 24, 2026 under BOD 22-01 for FCEB agencies. A Brotli library heap overflow (CVE-2026-111497, CVSS 9.8) and an Adobe Commerce / Magento RCE (CVE-2026-48356) have earlier due dates of November 10, 2026. Organizations should immediately identify WordPress, PHP-FPM, libbrotli, and Magento installations and apply available patches. PHP-FPM patched versions vary by minor branch; consult the PHP security advisory. The broad install base of WordPress (43%+ of the web) and PHP-FPM makes mass-exploitation at scale the primary threat model.
