# macOS ClickFix Browser-Fingerprinting Gate — AMOS and MacSync Infostealer Delivery

## Description

Detects the August 2026 evolution of the macOS ClickFix campaign, which added a server-side browser-fingerprinting gate to evade sandbox analysis and threat intelligence crawlers. The gate checks WebGL GPU renderer strings, `navigator.webdriver`, `toString()` intercept counters, and `Array.prototype.includes` tampering to exclude automated environments; only real macOS users on physical hardware receive the ClickFix lure.

Users who pass the fingerprint check are served a fake CAPTCHA or browser verification page instructing them to open Terminal and paste a curl command targeting a `/curl/<id>` staging endpoint. Successful execution installs AMOS (Atomic macOS Stealer) or MacSync, both targeting browser credentials, macOS Keychain, cryptocurrency wallets, SSH keys, and cloud credentials.

This detection is distinct from [macos_clickfix_fake_captcha_launchagent.md](macos_clickfix_fake_captcha_launchagent.md) (July 2026 campaign) in that it covers the new infrastructure IOCs (17 fruit-themed domains), the `/curl/<id>` staging URL pattern, and the AMOS/MacSync payload context.

**False positives:** curl commands with `/curl/`-path segments may appear in legitimate developer API calls (GitHub REST, some CDN APIs). Correlate with browser parent process or LaunchAgent creation for higher confidence. DNS hits on the listed domains have no legitimate business use.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Drive-by Compromise |
| Technique ID | T1189 |
| Secondary Tactic | Defense Evasion |
| Secondary Tactic ID | TA0005 |
| Secondary Technique | Execution Guardrails: Environmental Keying |
| Secondary Technique ID | T1480.001 |
| Tertiary Tactic | Credential Access |
| Tertiary Tactic ID | TA0006 |
| Tertiary Techniques | Credentials from Password Stores (T1555), Input Capture: Credential API Hooking (T1056.004) |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Delivery |
| Exploitation |
| Actions on Objectives |

## Splunk Detection Query

### Query 1 — DNS Lookup for Known August 2026 ClickFix Delivery Domains

```spl
| comment "IOC-based: August 2026 macOS ClickFix fingerprinting-gate delivery domains (Microsoft Security Blog 2026-08-05)"
index=* sourcetype IN ("stream:dns","syslog","crowdstrike","cisco:ise:syslog")
    query IN (
        "applefilevault.com",
        "apricotfilepoint.com",
        "bananafastfile.com",
        "cloudfilebridge.com",
        "filecedarwallet.online",
        "filecopperbasket.sbs",
        "filecrimsonsignal.online",
        "filemarblegarden.sbs",
        "fileoceanhammer.sbs",
        "filerubyfolder.sbs",
        "filevelvettractor.sbs",
        "lemonfilewave.com",
        "limefilescope.com",
        "mangocloudfile.com",
        "orangesmartfile.com",
        "syncdatavault.com",
        "cloudsendhub.com")
| eval risk_score=90
| stats count min(_time) as firstTime max(_time) as lastTime
    values(query) as dns_queries by src sourcetype risk_score
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime src sourcetype dns_queries risk_score
```

### Query 2 — curl Invocation Targeting /curl/ Staging Endpoint

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name="curl"
    AND Processes.process IN ("*/curl/*")
    AND Processes.parent_process_name IN (
        "Terminal","bash","zsh","sh",
        "Safari","Google Chrome","Firefox","Chromium","Brave Browser","Arc")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process,"(?i)/curl/[a-z0-9]{4,}") AND parent_process_name IN ("Safari","Google Chrome","Firefox","Chromium","Brave Browser","Arc"), 90,
    match(process,"(?i)/curl/[a-z0-9]{4,}") AND parent_process_name IN ("bash","zsh","sh","Terminal"), 80,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

### Query 3 — Web Proxy Request to /curl/ Staging Endpoint

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Web.Web
  where Web.uri_path="/curl/*"
    AND Web.http_method="GET"
  by Web.src Web.dest Web.uri_path Web.user_agent Web.http_method Web.url
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(uri_path,"^/curl/[a-z0-9]{4,}$"), 85,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime src dest uri_path user_agent http_method risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| DNS lookup matching any of the 17 known delivery domains | 90 | Known malicious infrastructure; no legitimate use |
| Browser spawning curl with /curl/<id> path argument | 90 | Direct behavioral signature of ClickFix payload retrieval via browser-triggered Terminal paste |
| Terminal/shell spawning curl with /curl/<id> path | 80 | Same pattern one step removed; user may have opened Terminal manually |
| Web proxy request to /curl/<alphanum> URI | 85 | Outbound web request to staging endpoint pattern |
| curl with /curl/ pattern but no contextual signals | 65 | Warrants analyst review; some legitimate APIs use this path structure |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown macOS ClickFix operators (August 2026) | [Microsoft Security Blog — macOS ClickFix Campaign Learned to Hide (2026-08-05)](https://www.microsoft.com/en-us/security/blog/2026/08/05/macos-clickfix-campaign-learned-hide/) |
| AMOS (Atomic macOS Stealer) operators | [MITRE ATT&CK S1100 — AMOS](https://attack.mitre.org/software/S1100/) |

## References

- [Microsoft Security Blog — macOS ClickFix campaign learned to hide (2026-08-05)](https://www.microsoft.com/en-us/security/blog/2026/08/05/macos-clickfix-campaign-learned-hide/)
- [Unit 42 Timely Threat Intel — macOS ClickFix campaign (July 8, 2026)](https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/2026-07-08-macOS-ClickFix-campaign.txt)
- [MITRE ATT&CK T1189 — Drive-by Compromise](https://attack.mitre.org/techniques/T1189/)
- [MITRE ATT&CK T1480.001 — Execution Guardrails: Environmental Keying](https://attack.mitre.org/techniques/T1480/001/)
- [MITRE ATT&CK T1555 — Credentials from Password Stores](https://attack.mitre.org/techniques/T1555/)
- [MITRE ATT&CK T1056.004 — Input Capture: Credential API Hooking](https://attack.mitre.org/techniques/T1056/004/)
- [MITRE ATT&CK S1100 — AMOS](https://attack.mitre.org/software/S1100/)
