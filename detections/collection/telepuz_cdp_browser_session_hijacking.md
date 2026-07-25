# TELEPUZ Chrome DevTools Protocol (CDP) Browser Session Hijacking

## Description

Detects the TELEPUZ malware's web injector module attaching to running Chrome or Edge browser instances via the Chrome DevTools Protocol (CDP) remote debugging interface to perform browser session hijacking without a browser extension. This technique, also usable by other MaaS platforms, exploits Chrome's legitimate remote automation interface — the same API used by Selenium, Playwright, and other testing tools — to inject JavaScript into active browser sessions targeting financial and credential entry sites.

The distinctive process behavior is a non-browser, non-testing parent process (e.g., `powershell.exe`, `cmd.exe`, a loader from `%APPDATA%`) launching Chrome or Chromium with `--remote-debugging-port` or `--remote-debugging-pipe` flags, or an unrecognized process making TCP connections to the Chrome DevTools port (default 9222) on localhost. Legitimate use of remote debugging by developers or CI/CD systems should be tuned out by suppressing known testing framework process names and paths.

False positives: Playwright/Selenium test runners (identified by `node.exe`, `pytest`, `pytest.exe` parent processes or command lines containing `--test` / test framework paths); VS Code extension host; Chrome launched from a managed device policy for kiosk mode.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Collection |
| Tactic ID | TA0009 |
| Technique | Browser Session Hijacking |
| Technique ID | T1185 |
| Secondary Tactic | Credential Access |
| Secondary Tactic ID | TA0006 |
| Secondary Technique | Credentials from Password Stores: Credentials from Web Browsers |
| Secondary Technique ID | T1555.003 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Actions on Objectives |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name IN ("chrome.exe","chromium.exe","chromium","msedge.exe","brave.exe")
    AND (match(Processes.process, "(?i)--remote-debugging-port|--remote-debugging-pipe|--remote-allow-origins")
         OR match(Processes.process, "(?i)--disable-extensions.*--load-extension|--headless"))
    AND NOT Processes.parent_process_name IN ("node.exe","python.exe","python3","pytest",
        "java.exe","code.exe","code","electron.exe","playwright","webdriver","chromedriver",
        "geckodriver","msedgedriver")
    AND NOT match(Processes.parent_process, "(?i)/usr/share/|/opt/|AppData\\\\Local\\\\Programs\\\\Microsoft VS Code")
  by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| eval risk_score=case(
    match(parent_process_name, "(?i)powershell|pwsh|cmd"), 95,
    match(process, "(?i)--remote-debugging-port") AND NOT match(parent_process_name, "(?i)node|python|java|code"), 88,
    match(process, "(?i)--disable-extensions.*--load-extension"), 85,
    1=1, 75)
| where risk_score >= 85
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user parent_process_name parent_process process_name process risk_score
```

**Supplemental: Suspicious process connecting to localhost Chrome DevTools port**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest IN ("127.0.0.1","::1","localhost")
    AND All_Traffic.dest_port >= 9222
    AND All_Traffic.dest_port <= 9229
    AND NOT All_Traffic.app IN ("chrome","chromium","msedge","brave","node","python","java")
  by All_Traffic.src_ip All_Traffic.dest All_Traffic.dest_port All_Traffic.app
     All_Traffic.src_port
| `drop_dm_object_name(All_Traffic)`
| eval risk_score=case(
    NOT match(app, "(?i)chrome|chromium|edge|brave|node|python|java|selenium|playwright"), 90,
    1=1, 75)
| where risk_score >= 90
| lookup dnslookup clientip as src_ip output clienthost
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime src_ip clienthost dest_port app risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Chrome launched with `--remote-debugging-port` from `powershell.exe` or `cmd.exe` | 95 | No legitimate workflow launches Chrome with remote debugging from a script host; direct TELEPUZ/MaaS injection pattern |
| Chrome with remote debugging from non-testing, non-IDE parent | 88 | Uncommon; should be tuned against known test frameworks in environment |
| Chrome with `--disable-extensions` + `--load-extension` (sideloading) | 85 | Extension injection pattern used by some credential-stealing MaaS variants |
| Unknown process making TCP connection to localhost CDP port range (9222–9229) | 90 | CDP is only legitimately consumed by DevTools UI, test frameworks, or browser tooling |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| TELEPUZ MaaS Operator | [Elastic Security Labs — TELEPUZ (2026-07-16)](https://www.elastic.co/security-labs/telepuz-maas-malware-clickfix) |
| Golden Chickens (TAG-195) | [Recorded Future — TAG-195 MaaS Evolution (2026-07-24)](https://www.recordedfuture.com/research/tag-195-evolves-maas-ecosystem) |

## References

- [Elastic Security Labs — TELEPUZ: MaaS Malware via ClickFix (2026-07-16)](https://www.elastic.co/security-labs/telepuz-maas-malware-clickfix)
- [Chrome DevTools Protocol documentation](https://chromedevtools.github.io/devtools-protocol/)
- [MITRE ATT&CK — T1185 Browser Session Hijacking](https://attack.mitre.org/techniques/T1185/)
- [MITRE ATT&CK — T1555.003 Credentials from Password Stores: Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003/)
