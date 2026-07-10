---
scraped_at: "2026-07-10T09:30:00Z"
source_url: "https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/2026-07-08-macOS-ClickFix-campaign.txt"
report_type: threat-intel
severity: medium
title: "macOS ClickFix Campaign: Fake Browser Verification Pages via Paid Ads Deliver Bash Script with LaunchAgent Persistence (Active July 3–8, 2026)"
---

## 1. IOCs

### Redirector

| Type | Indicator | Context |
|------|-----------|---------|
| Domain | `grabora[.]org` | Paid-ad affiliate cloaking and traffic distribution redirector; campaign ID 11209365; routes to Cloudflare Pages lure domains |

### Fake CAPTCHA / Verification Lure Domains (Cloudflare Pages)

| Type | Indicator | Context |
|------|-----------|---------|
| Domain | `browseraccess4.pages[.]dev` | Fake browser access / CAPTCHA verification lure page |
| Domain | `goprocessing-1exo.pages[.]dev` | Fake processing / verification lure page |
| Domain | `justamomentonenit.pages[.]dev` | Fake verification lure page |
| Domain | `securesession2.pages[.]dev` | Fake secure session verification lure page |
| Domain | `trustbridge-secureidentitygatewayv2.pages[.]dev` | Fake identity gateway verification lure page |
| Domain | `verifly-identitycheckv2proceed.pages[.]dev` | Fake Verifly identity check lure page |
| Domain | `verifly-instant-idcheckv2.pages[.]dev` | Fake Verifly instant identity check lure page |
| Domain | `vp-secureidgateway.pages[.]dev` | Fake secure ID gateway verification lure page |

### Payload Delivery Domains (malicious update.sh hosting)

| Type | Indicator | Context |
|------|-----------|---------|
| Domain | `alph6b4.uploadphrase[.]top` | Hosts malicious update.sh bash script payload |
| Domain | `content-edge01.betgo[.]pro` | Hosts malicious update.sh bash script payload |
| Domain | `etas7zeh.scabbysurvey[.]top` | Hosts malicious update.sh bash script payload |
| Domain | `januic.dumanbett[.]co` | Hosts malicious update.sh bash script payload |
| Domain | `marezf.jackknifeautomaker[.]top` | Hosts malicious update.sh bash script payload |
| Domain | `member-portal01.linebetfa[.]com` | Hosts malicious update.sh bash script payload |
| Domain | `onliwp.303ine[.]com` | Hosts malicious update.sh bash script payload |
| Domain | `results-center01.pishbini[.]win` | Hosts malicious update.sh bash script payload |
| Domain | `systdg5o.enobahiss[.]xyz` | Hosts malicious update.sh bash script payload |

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|--------------|----------------|-------|
| Initial Access | TA0001 / T1189 | Drive-by Compromise | Victim reaches fake verification page via paid ad (Google Ads or similar) routed through grabora[.]org redirector |
| Execution | TA0002 / T1204.002 | User Execution: Malicious File | ClickFix lure instructs macOS user to open Terminal and paste/run a curl command; social engineering to trigger self-execution |
| Execution | TA0002 / T1059.004 | Command and Scripting Interpreter: Unix Shell | Pasted command downloads and executes `update.sh` bash script via curl |
| Persistence | TA0003 / T1543.001 | Create or Modify System Process: Launch Agent | update.sh installs a LaunchAgent plist in `~/Library/LaunchAgents/` via osascript for user-session persistence |
| Defense Evasion | TA0005 / T1036 | Masquerading | Payload filename `update.sh` and Cloudflare Pages infrastructure blend with legitimate software distribution |

---

## 3. Malware & Tools

| Item | Type | Notes |
|------|------|-------|
| update.sh | Bash dropper | Downloaded from one of 9 payload delivery domains via curl; installs LaunchAgent for persistence; exact payload functionality (C2, credential theft, etc.) not detailed in Unit 42 disclosure |

---

## 4. Threat Actor / Campaign Attribution

- **Attribution:** Unknown; assessed as financially motivated (likely infostealer delivery based on the LaunchAgent persistence pattern common to macOS infostealers)
- **Campaign start:** July 3, 2026
- **Platform:** macOS-specific (ClickFix instructions tailored for Terminal; LaunchAgent persistence)
- **Distribution model:** Paid advertising (Google Ads or similar) routing through grabora[.]org affiliate redirector with campaign tracking ID
- **Infrastructure:** Cloudflare Pages for lure hosting (shared CDN, low-cost, trusted domain reputation); separate per-victim payload delivery domains

---

## 5. Splunk Detection Searches

```spl
| comment "Detect macOS ClickFix: browser spawning Terminal or osascript — user copied and pasted ClickFix command"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN ("Safari","Google Chrome","Firefox","Chromium","Brave Browser","Arc","opera")
    AND Processes.process_name IN ("osascript","bash","zsh","sh","curl","Terminal")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    process_name="osascript" AND match(process,"(?i)(LaunchAgent|launchctl|plutil|plist)"), 90,
    process_name="osascript"                                                               , 80,
    process_name IN ("bash","zsh","sh") AND match(process,"(?i)(curl|wget|update\.sh)")   , 85,
    process_name="curl" AND match(process,"(?i)(update\.sh|pages\.dev|\.top|\.xyz|\.win)"), 75,
    1=1                                                                                    , 60)
| where risk_score >= 60
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| comment "Detect LaunchAgent plist creation in user Library by non-system processes (macOS persistence)"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_path="*/Library/LaunchAgents/*.plist"
    AND Filesystem.action IN ("created","modified","write")
    NOT Filesystem.process_name IN ("launchd","cfprefsd","System Preferences","softwareupdate",
                                     "com.apple.ManagedClient","mdmclient")
  by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_name Filesystem.file_path
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_name,"(?i)(osascript|bash|zsh|python|perl|ruby|curl)"), 85,
    1=1                                                                  , 70)
| where risk_score >= 70
| table firstTime lastTime dest user process_name file_name file_path risk_score
```

```spl
| comment "Network IOC: DNS lookup or connection to macOS ClickFix lure/payload domains (July 2026 campaign)"
index=* sourcetype IN ("stream:dns","syslog","crowdstrike","cisco:ise:syslog")
    (query IN (
        "grabora.org",
        "browseraccess4.pages.dev","goprocessing-1exo.pages.dev","justamomentonenit.pages.dev",
        "securesession2.pages.dev","trustbridge-secureidentitygatewayv2.pages.dev",
        "verifly-identitycheckv2proceed.pages.dev","verifly-instant-idcheckv2.pages.dev",
        "vp-secureidgateway.pages.dev",
        "uploadphrase.top","betgo.pro","scabbysurvey.top","dumanbett.co",
        "jackknifeautomaker.top","linebetfa.com","303ine.com","pishbini.win","enobahiss.xyz")
    OR dest IN (
        "grabora.org","uploadphrase.top","betgo.pro","scabbysurvey.top","dumanbett.co",
        "jackknifeautomaker.top","linebetfa.com","303ine.com","pishbini.win","enobahiss.xyz"))
| eval risk_score=case(
    match(query,"(?i)(uploadphrase|betgo\.pro|scabbysurvey|dumanbett|jackknifeautomaker|linebetfa|303ine|pishbini|enobahiss)"), 90,
    match(query,"(?i)grabora\.org")                                                                                           , 85,
    match(query,"(?i)pages\.dev")                                                                                             , 60,
    1=1                                                                                                                       , 70)
| stats count min(_time) as firstTime max(_time) as lastTime
    values(query) as dns_queries values(dest) as dest_domains
    by src sourcetype risk_score
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime src sourcetype dns_queries dest_domains risk_score
```

---

## 6. Executive Summary

A macOS-targeted ClickFix campaign active since July 3, 2026 distributes a malicious bash script (`update.sh`) via paid advertising. Victims reach the attack chain through a paid ad that routes via the `grabora[.]org` redirector (affiliate cloaking with campaign ID 11209365) to one of eight fake browser verification / CAPTCHA lure pages hosted on Cloudflare Pages subdomains. The lure instructs the user to open Terminal and paste a command, which downloads and executes `update.sh` from one of nine payload delivery domains. The script installs a LaunchAgent for user-session persistence.

The ClickFix social engineering vector — instructing users to manually execute a copied command — is increasingly common across both Windows and macOS campaigns because it bypasses browser-level download warnings and AV scanning of auto-downloaded files. The use of Cloudflare Pages for lure hosting provides SSL and trusted domain reputation; network-layer blocking of `*.pages.dev` requires subdomain-level IOC matching. Detection is most reliable at the process level: browser processes spawning Terminal, osascript, or curl are strong behavioral signals regardless of which specific lure domain is used.

**Severity: Medium.** Individual victim impact depends on the update.sh payload (likely infostealer based on the LaunchAgent persistence pattern seen in similar macOS campaigns). The paid-ad distribution model provides broad reach; macOS users are less likely to have EDR coverage compared to Windows endpoints.

---

## References

- [Unit 42 Timely Threat Intel — macOS ClickFix campaign (July 8, 2026)](https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/2026-07-08-macOS-ClickFix-campaign.txt)
- [MITRE ATT&CK T1189 — Drive-by Compromise](https://attack.mitre.org/techniques/T1189/)
- [MITRE ATT&CK T1204.002 — User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
- [MITRE ATT&CK T1059.004 — Command and Scripting Interpreter: Unix Shell](https://attack.mitre.org/techniques/T1059/004/)
- [MITRE ATT&CK T1543.001 — Create or Modify System Process: Launch Agent](https://attack.mitre.org/techniques/T1543/001/)
