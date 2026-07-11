---
scraped_at: "2026-07-09T00:00:00Z"
source_url: "https://socradar.io/blog/wp-shellstorm-expose-1-4m-wordpress-sites/"
report_type: threat-intel
severity: high
title: "WP-SHELLSTORM: Exposed Operator Server Reveals Webshell Brokerage Targeting 1.4M+ WordPress and Joomla Sites"
---

## 1. IOCs

### IP Addresses

| IP | Context |
|----|---------|
| `137.175.93[.]126` | WP-SHELLSTORM operator server; exposed directory containing 800MB of webshells, exploit scripts, scan results, bash history, and C2 configuration; discovered by SOCRadar June 11 2026 |

### File Hashes

| Hash | Type | Filename | Context |
|------|------|----------|---------|
| `84F7E396A48913851A10CC78C5CC22A25634564ABD0694465236D2F365E2BDEE` | SHA256 | `down.php` | WP-SHELLSTORM primary backdoor; 4-layer obfuscated PHP webshell derived from BestShell open-source Chinese webshell; deployed across 5,700+ compromised sites |

### Webshell Filenames / Paths

| Filename Pattern | Context |
|-----------------|---------|
| `.bd.php` | WP-SHELLSTORM hidden PHP webshell; leading dot for filesystem concealment on Linux hosts |
| `.wp-log.php` | WP-SHELLSTORM hidden PHP webshell disguised as WordPress log file |
| `.brq-*.php` | WP-SHELLSTORM variant webshell with randomized suffix |
| `.sd.php` | WP-SHELLSTORM hidden PHP webshell |
| `.leo_*.php` | WP-SHELLSTORM variant webshell with suffix |
| `.wvp-*.php` | WP-SHELLSTORM variant webshell with suffix |
| `.cc-*.php` | WP-SHELLSTORM variant webshell with suffix |
| `.nf-log.php` | WP-SHELLSTORM hidden PHP webshell disguised as log file |
| `BZ_*.phtml` | WP-SHELLSTORM PHP webshell using .phtml extension to evade .php extension blocking |

### CVEs Exploited

| CVE | Component | CVSS | Description |
|-----|-----------|------|-------------|
| CVE-2026-3844 | WordPress Breeze Cache Plugin | 9.8 | Unauthenticated arbitrary file upload via cache directory traversal; primary exploit vector; 45,000+ installations targeted; 17,000+ backdoored |
| (26 additional CVEs) | Various WordPress/Joomla plugins | Various | Full list on operator server; targets included form builders, page builders, e-commerce extensions, and SEO plugins |

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|---------------|-------|
| Initial Access | T1190 | Exploit Public-Facing Application | Automated exploitation of 27 CVEs across WordPress and Joomla plugins; CVE-2026-3844 Breeze Cache Plugin (CVSS 9.8) is primary vector |
| Persistence | T1505.003 | Server Software Component: Web Shell | 4-layer obfuscated PHP webshells deployed to compromised sites; filenames use leading dots and .phtml extensions for concealment; derived from open-source BestShell codebase |
| Reconnaissance | T1595.002 | Active Scanning: Vulnerability Scanning | Operator server contained scan results against 1.4M+ domains; bash history shows automated bulk scanning |
| Resource Development | T1587.001 | Develop Capabilities: Malware | Custom 4-layer PHP obfuscation wrapping BestShell base; 800MB of webshell variants and exploit scripts found on operator server |
| Command and Control | T1102 | Web Service | Compromised WordPress/Joomla sites resold as webshell access to downstream buyers; operator server hosts C2 configuration for aggregated shell management |

---

## 3. Malware & Tools

| Component | Type | Description |
|-----------|------|-------------|
| `down.php` (BestShell derivative) | PHP Webshell | Primary backdoor; 4-layer PHP obfuscation using `eval(base64_decode(...))` chains; based on BestShell open-source Chinese webshell; provides full server control including file manager, command execution, and database access |
| WP-SHELLSTORM exploit pack | Exploit Bundle | 800MB archive on operator server including 27-CVE exploit scripts targeting WordPress and Joomla plugins, automated mass-scanning tools, and bash scripts for bulk deployment |
| Hidden PHP variants (.bd.php, .nf-log.php, etc.) | PHP Webshell Variants | Secondary webshells using leading-dot filenames to hide from `ls` without `-a` flag; `.phtml` extension variants evade extension-based blocking rules |

---

## 4. Threat Actor / Campaign Attribution

| Field | Value |
|-------|-------|
| Actor Name | Unknown (WP-SHELLSTORM operator) |
| Attribution | Unattributed; BestShell open-source Chinese webshell lineage suggests Chinese-speaking origin; operates as webshell access brokerage |
| Discovery | SOCRadar identified exposed operator server (137.175.93[.]126) on June 11 2026; directory listing enabled; no authentication on operator's own infrastructure |
| Campaign Scale | 1.4M+ domains targeted; 5,700+ WordPress/Joomla sites compromised; 17,000+ backdoored via CVE-2026-3844 (Breeze Cache Plugin) alone |
| Business Model | Webshell access brokerage; operator sells authenticated webshell access to compromised sites to downstream buyers (ransomware affiliates, spam operators, SEO poisoners) |
| Targeting | Indiscriminate; automated bulk scanning across all accessible WordPress and Joomla installations; no sector specificity |

---

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Web.Web
where (Web.uri="*/.bd.php" OR Web.uri="*/.wp-log.php" OR Web.uri="*/.nf-log.php"
  OR Web.uri="*/.sd.php" OR Web.uri="*/.brq-*.php" OR Web.uri="*/.leo_*.php"
  OR Web.uri="*/.wvp-*.php" OR Web.uri="*/.cc-*.php" OR Web.uri="*/BZ_*.phtml")
by Web.src Web.dest Web.uri Web.http_user_agent Web.status Web.http_method
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    (uri="*/.bd.php" OR uri="*/.wp-log.php" OR uri="*/.nf-log.php"), 90,
    (uri="*/BZ_*.phtml"), 85,
    1=1, 80)
| where risk_score >= 80
| table firstTime lastTime src dest uri status http_method risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.dest="137.175.93.126"
by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.action
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| eval detection="WP-SHELLSTORM_C2_Operator_Server"
| table firstTime lastTime src dest dest_port action risk_score detection
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where (Filesystem.file_name=".bd.php" OR Filesystem.file_name=".wp-log.php"
  OR Filesystem.file_name=".nf-log.php" OR Filesystem.file_name=".sd.php"
  OR Filesystem.file_name LIKE ".brq-%.php" OR Filesystem.file_name LIKE ".leo_%.php"
  OR Filesystem.file_name LIKE ".wvp-%.php" OR Filesystem.file_name LIKE ".cc-%.php"
  OR Filesystem.file_name LIKE "BZ_%.phtml")
  AND (Filesystem.file_path="*/wp-content/*" OR Filesystem.file_path="*/public_html/*"
    OR Filesystem.file_path="*/htdocs/*" OR Filesystem.file_path="*/www/*")
by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.action
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| eval detection="WP-SHELLSTORM_Webshell_File_Creation"
| table firstTime lastTime dest user file_name file_path action risk_score detection
```

---

## 6. Executive Summary

In June 2026, SOCRadar discovered an exposed operator server (`137.175.93[.]126`) belonging to the WP-SHELLSTORM webshell access brokerage — a threat actor conducting automated mass exploitation of WordPress and Joomla sites to resell compromised webshell access. The exposed server contained 800MB of operational data including webshell variants, exploit scripts for 27 CVEs, bulk scanning results covering 1.4M+ domains, operator bash history, and C2 configuration.

The primary exploit vector is CVE-2026-3844, an unauthenticated arbitrary file upload vulnerability (CVSS 9.8) in the WordPress Breeze Cache Plugin affecting 45,000+ installations. The operator backdoored over 17,000 sites via this single CVE alone, with 5,700+ total compromised sites across both WordPress and Joomla platforms.

Webshells follow distinctive naming conventions: hidden PHP files using leading dots (`.bd.php`, `.wp-log.php`, `.nf-log.php`) to evade standard directory listings, and `.phtml` extension variants (`BZ_*.phtml`) to bypass `.php` extension blocking in web server configurations. The primary backdoor (`down.php`, SHA256: `84F7E396A48913851A10CC78C5CC22A25634564ABD0694465236D2F365E2BDEE`) is a 4-layer obfuscated PHP webshell derived from the open-source Chinese BestShell codebase, suggesting a Chinese-speaking operator.

**Immediate actions:** Scan all WordPress/Joomla web roots for files matching `.bd.php`, `.wp-log.php`, `.nf-log.php`, `.sd.php`, and `BZ_*.phtml` patterns. Block `137.175.93[.]126` at the perimeter. Patch or disable the Breeze Cache Plugin (CVE-2026-3844, patched in version 2.1.2). Check web server access logs for requests to these hidden filenames dating back to April 2026.

---

## References

- [SOCRadar — WP-SHELLSTORM: Exposing 1.4M WordPress Sites](https://socradar.io/blog/wp-shellstorm-expose-1-4m-wordpress-sites/)
- [NVD CVE-2026-3844 — Breeze Cache Plugin Unauthenticated File Upload](https://nvd.nist.gov/vuln/detail/CVE-2026-3844)
- [MITRE ATT&CK T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK T1505.003 — Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003/)
- [MITRE ATT&CK T1595.002 — Active Scanning: Vulnerability Scanning](https://attack.mitre.org/techniques/T1595/002/)
