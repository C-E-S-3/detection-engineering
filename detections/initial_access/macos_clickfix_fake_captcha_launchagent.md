# macOS ClickFix: Fake Browser Verification Spawning Terminal Execution and LaunchAgent Persistence

## Description

Detects the macOS ClickFix social engineering technique where fake browser verification or CAPTCHA pages instruct users to open Terminal and paste a command. The pasted command typically invokes `curl` or `bash` to download and execute a malicious script (commonly named `update.sh`) that installs a LaunchAgent for persistence. This technique bypasses browser download warnings because the user executes the payload manually.

The campaign active since July 3, 2026 uses paid advertising routing through `grabora[.]org` to Cloudflare Pages lure domains, then downloads bash payloads from a fleet of short-lived hosting domains.

**False positives:** Developers or power users running curl commands from Terminal; legitimate macOS software installed via shell scripts; MDM-managed software deployment may create LaunchAgent plists. Correlate browser-spawned shell execution with LaunchAgent creation for higher confidence.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Drive-by Compromise |
| Technique ID | T1189 |
| Secondary Tactic | Execution |
| Secondary Tactic IDs | TA0002 |
| Secondary Techniques | User Execution: Malicious File (T1204.002), Command and Scripting Interpreter: Unix Shell (T1059.004) |
| Tertiary Tactic | Persistence |
| Tertiary Tactic ID | TA0003 |
| Tertiary Technique | Create or Modify System Process: Launch Agent |
| Tertiary Technique ID | T1543.001 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Delivery |
| Exploitation |
| Installation |

## Splunk Detection Query

### Query 1 — Browser Spawning Shell Interpreter or osascript (ClickFix Execution)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN (
        "Safari","Google Chrome","Firefox","Chromium","Brave Browser","Arc","Opera","Microsoft Edge")
    AND Processes.process_name IN ("osascript","bash","zsh","sh","curl","wget")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    process_name="osascript" AND match(process,"(?i)(LaunchAgent|launchctl|plutil|plist)"), 90,
    process_name="osascript"                                                               , 80,
    process_name IN ("bash","zsh","sh") AND match(process,"(?i)(curl|wget|update\.sh)")   , 85,
    process_name="curl" AND match(process,"(?i)(update\.sh|\.top/|\.xyz/|\.win/|\.pro/|pages\.dev)"), 80,
    1=1                                                                                    , 65)
| where risk_score >= 65
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

### Query 2 — LaunchAgent Plist Creation by Non-System Process (Persistence Stage)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_path="*/Library/LaunchAgents/*.plist"
    AND Filesystem.action IN ("created","modified","write")
    NOT Filesystem.process_name IN (
        "launchd","cfprefsd","System Preferences","softwareupdate",
        "com.apple.ManagedClient","mdmclient","jamf","munki","Chef")
  by Filesystem.dest Filesystem.user Filesystem.process_name
     Filesystem.file_name Filesystem.file_path
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_name,"(?i)(osascript|bash|zsh|sh|python|perl|ruby|curl|wget)"), 85,
    1=1                                                                          , 70)
| where risk_score >= 70
| table firstTime lastTime dest user process_name file_name file_path risk_score
```

### Query 3 — DNS Lookup for Known ClickFix Campaign Domains (July 2026)

```spl
| comment "IOC-based: July 2026 macOS ClickFix campaign domains from Unit 42"
index=* sourcetype IN ("stream:dns","syslog","crowdstrike","cisco:ise:syslog")
    query IN (
        "grabora.org",
        "uploadphrase.top","betgo.pro","scabbysurvey.top","dumanbett.co",
        "jackknifeautomaker.top","linebetfa.com","303ine.com","pishbini.win","enobahiss.xyz",
        "browseraccess4.pages.dev","goprocessing-1exo.pages.dev","justamomentonenit.pages.dev",
        "securesession2.pages.dev","trustbridge-secureidentitygatewayv2.pages.dev",
        "verifly-identitycheckv2proceed.pages.dev","verifly-instant-idcheckv2.pages.dev",
        "vp-secureidgateway.pages.dev")
| eval risk_score=case(
    match(query,"(?i)(uploadphrase|betgo\.pro|scabbysurvey|dumanbett|jackknifeautomaker|linebetfa|303ine|pishbini|enobahiss)"), 90,
    match(query,"(?i)grabora\.org")                                                                                           , 85,
    match(query,"(?i)pages\.dev")                                                                                             , 60,
    1=1                                                                                                                       , 70)
| stats count min(_time) as firstTime max(_time) as lastTime
    values(query) as dns_queries by src sourcetype risk_score
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime src sourcetype dns_queries risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Browser spawning osascript with LaunchAgent reference | 90 | Near-certain ClickFix persistence stage; osascript creating plists is not a normal browser child process behavior |
| Browser spawning bash/sh downloading update.sh | 85 | Strong behavioral match to ClickFix execution pattern |
| Browser spawning osascript (no LaunchAgent reference) | 80 | Highly suspicious; browsers should not spawn osascript under any normal circumstance |
| curl from browser with payload domain TLD pattern | 80 | Browser spawning curl suggests user pasted a download command |
| LaunchAgent plist created by osascript/bash/curl | 85 | Persistence stage; non-system process writing to LaunchAgents is anomalous |
| LaunchAgent plist created by unlisted process | 70 | Broad catch; warrants analyst review |
| DNS lookup for payload delivery domain | 90 | Known malicious infrastructure from July 2026 campaign |
| DNS lookup for grabora.org | 85 | Known ClickFix cloaking redirector |
| DNS lookup for lure .pages.dev subdomain | 60 | Shared infrastructure; lower confidence without correlated process activity |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown macOS ClickFix operator (July 2026) | [Unit 42 Timely Threat Intel — macOS ClickFix campaign (July 8, 2026)](https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/2026-07-08-macOS-ClickFix-campaign.txt) |

## References

- [Unit 42 Timely Threat Intel — macOS ClickFix campaign (July 8, 2026)](https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/2026-07-08-macOS-ClickFix-campaign.txt)
- [MITRE ATT&CK T1189 — Drive-by Compromise](https://attack.mitre.org/techniques/T1189/)
- [MITRE ATT&CK T1204.002 — User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
- [MITRE ATT&CK T1059.004 — Command and Scripting Interpreter: Unix Shell](https://attack.mitre.org/techniques/T1059/004/)
- [MITRE ATT&CK T1543.001 — Create or Modify System Process: Launch Agent](https://attack.mitre.org/techniques/T1543/001/)
