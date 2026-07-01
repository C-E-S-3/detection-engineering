---
scraped_at: 2026-07-01T00:00:00Z
source_url: https://www.microsoft.com/en-us/security/blog/2026/06/29/chromium-extension-uses-airelated-branding-redirect-browser-search/
report_type: threat-intel
severity: medium
title: Fake "Perplexity AI" Chrome Extension Intercepts All Browser Searches and Address-Bar Keystrokes
---

## 1. IOCs

### Domains
| Indicator | Context |
|-----------|---------|
| `perplexity-ai[.]online` | Attacker typosquatted domain — all address-bar queries and search suggestions are routed through this server before redirection to legitimate results; nginx config explicitly logs method, URL, and full HTTP headers |
| `oda[.]digital` | Operator backend infrastructure referenced in extension's nginx configuration; assessed as attacker-controlled |
| `extension.tilda[.]ws/perplexityai` | Onboarding/landing page for the malicious extension (hosted on Tilda website builder by attacker) |

### Browser Extension Artifacts
| Artifact | Value | Context |
|----------|-------|---------|
| Chrome Extension ID | `flkebkiofojicogddingbdmcmkpbplcd` | "Search for perplexity ai" — Manifest Version 3, version 2.2; removed from Chrome Web Store after Microsoft responsible disclosure June 29 2026 |

### File Hashes
None published in original report.

### IPs
None published in original report.

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Procedure |
|--------|-------------|----------------|-----------|
| Initial Access | T1189 | Drive-by Compromise | Extension distributed via Chrome Web Store posing as the Perplexity AI answer engine |
| Defense Evasion | T1036 | Masquerading | Extension uses Perplexity AI branding (logo, name, descriptions) and installs without anomalous alerts |
| Collection | T1056.004 | Input Capture: Credential API Hooking | `suggest_url` parameter routes every character typed in the browser address bar through attacker-controlled server; real-time keylogging of all queries and autocomplete suggestions |
| Collection | T1185 | Browser Session Hijacking | `declarativeNetRequest` rules intercept all search traffic before forwarding to legitimate search providers |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | All intercepted query data POST-routed over HTTPS to `perplexity-ai[.]online` |
| Persistence | T1176 | Browser Extensions | Manifest V3 extension hijacks `chrome_settings_overrides` to set itself as the default search provider; survives browser restarts |

**MV3 Permissions Abused:**
- `declarativeNetRequest`
- `declarativeNetRequestFeedback`
- `declarativeNetRequestWithHostAccess`
- `chrome_settings_overrides` (forced default search provider override)

---

## 3. Malware & Tools

| Name | Type | Description |
|------|------|-------------|
| "Search for perplexity ai" | Malicious Browser Extension | Manifest V3 Chrome extension; routes all address-bar input through attacker infrastructure; does NOT install additional malware but passively harvests search queries, browsing signals, and HTTP metadata (method, URL, headers, User-Agent, source IP) |

**Data harvested per the extension's server-side logging code:**
- Full URL of every request
- HTTP method
- All request headers (including `Cookie`, `Authorization` where present in search requests)
- User-Agent string
- Source IP address

---

## 4. Threat Actor / Campaign Attribution

No threat actor attribution identified in Microsoft's disclosure. The operator backend domain `oda[.]digital` may be usable for future infrastructure correlation. The extension was removed from the Chrome Web Store following Microsoft's responsible disclosure on June 29, 2026.

---

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Resolution.DNS
  where DNS.query IN ("perplexity-ai.online", "oda.digital")
  by DNS.src DNS.dest DNS.query
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime src dest query risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Web.Web
  where Web.dest IN ("perplexity-ai.online", "oda.digital")
  by Web.src Web.dest Web.url Web.http_method Web.user_agent
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime src dest url http_method user_agent risk_score
```

---

## 6. Executive Summary

On June 29, 2026, Microsoft Threat Intelligence disclosed a malicious Chromium browser extension ("Search for perplexity ai", ID `flkebkiofojicogddingbdmcmkpbplcd`) distributed through the Chrome Web Store. The extension masqueraded as the Perplexity AI answer engine and hijacked the browser's default search provider to silently route **every character typed in the address bar** through attacker-controlled infrastructure (`perplexity-ai[.]online`) before forwarding to legitimate search results.

Users received normal search results and experienced no visible anomaly. The extension's server-side nginx config explicitly logged all incoming HTTP requests — including full URLs, headers, and source IPs — indicating deliberate, systematic data collection. No malware installation or credential theft beyond search query interception was confirmed; however, queries typed in address bars frequently contain sensitive terms (internal domain names, search terms hinting at internal tools, etc.).

Google removed the extension from the Chrome Web Store following Microsoft's responsible disclosure. Organizations should check for the extension ID `flkebkiofojicogddingbdmcmkpbplcd` in enterprise browser management policies, block DNS resolution to `perplexity-ai.online`, and hunt proxy logs for outbound traffic to this domain.

**Severity: Medium** — The technique is passive (search query interception) rather than credential-stealing malware; the specific extension was removed. Organizations with MDM/browser policy controls can audit and remediate quickly.
