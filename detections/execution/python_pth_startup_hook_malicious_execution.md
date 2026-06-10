# Malicious Python PTH Startup Hook Execution — Supply Chain Persistence via Site-Packages

## Description

Detects malicious use of Python `.pth` (path configuration) files placed in a Python interpreter's `site-packages` or `dist-packages` directory to achieve automatic code execution whenever the Python interpreter starts. Legitimate `.pth` files simply add directories to `sys.path`; however, Python evaluates any line starting with `import ` in a `.pth` file as an actual import statement, and some Python implementations execute non-path lines as `exec()` calls. This means an attacker who can write to `site-packages` (e.g., via a trojanized pip package) can install persistent code execution that triggers before any user-controlled code runs — including in CI/CD runners, developer tools, and virtual environments.

Observed in the Shai-Hulud "Hades" wave (June 2026), which trojanized 19 PyPI bioinformatics packages by shipping a `*-setup.pth` file that (1) downloads the legitimate Bun JavaScript runtime from GitHub and (2) executes an obfuscated `_index.js` credential harvester stealing developer and cloud secrets.

False positive sources: Legitimate packages occasionally ship `.pth` files for namespace packages or editable installs (`pip install -e .`); these should be expected and can be baselined. The suspicious signal is a `.pth` file triggering subprocess execution (especially of curl/wget/bun toward external hosts) or creation of a `.pth` file in a non-development context (CI/CD runner, production server).

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Execution |
| Tactic ID | TA0002 |
| Technique | Command and Scripting Interpreter: Python |
| Technique ID | T1059.006 |
| Secondary Tactic | Persistence |
| Secondary Tactic ID | TA0003 |
| Secondary Technique | Event Triggered Execution |
| Secondary Technique ID | T1546 |
| Tertiary Tactic | Initial Access |
| Tertiary Technique | Supply Chain Compromise: Compromise Software Dependencies |
| Tertiary Technique ID | T1195.001 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Installation |

## Splunk Detection Query

```spl
| comment "Query 1: Python spawning curl/wget/bun to download Bun runtime from GitHub — triggered by malicious .pth startup hook"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.parent_process_name IN ("python.exe","python","python3","python3.11","python3.12","python3.13")
         OR Processes.parent_process="*python*")
    AND Processes.process_name IN ("curl","wget","bun","bun.exe")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    process_name IN ("bun","bun.exe"), 90,
    match(process,"(?i)github\.com.*(bun|oven-sh)"), 90,
    match(process,"(?i)github\.com"), 80,
    process_name IN ("curl","wget"), 75,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| comment "Query 2: New .pth file created in Python site-packages or dist-packages — possible supply chain startup hook installation"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_name="*.pth"
    AND (Filesystem.file_path="*site-packages*"
         OR Filesystem.file_path="*dist-packages*"
         OR Filesystem.file_path="*Lib\\site-packages*")
  by Filesystem.dest Filesystem.user Filesystem.file_path
     Filesystem.file_name Filesystem.action
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(file_name,"(?i)setup\.pth|install\.pth|run\.pth"), 80,
    action="created", 75,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime dest user file_path file_name action risk_score
```

```spl
| comment "Query 3: Bun or Node.js executing _index.js in temp/cache directories — Hades wave Bun Stealer payload execution"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.process_name IN ("bun","bun.exe","node","node.exe"))
    AND (Processes.process="*_index.js*"
         OR Processes.process="*/tmp/*"
         OR Processes.process="*\\Temp\\*"
         OR Processes.process="*/.cache/*")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process,"(?i)_index\.js"), 95,
    match(process,"(?i)/tmp/|\\\\Temp\\\\|/.cache/"), 85,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| comment "Query 4: GitHub repository creation API calls from developer workstations — Shai-Hulud exfiltration via auto-created repos"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Web.Web
  where Web.dest_host="api.github.com"
    AND Web.http_method="POST"
    AND (Web.uri_path="*/user/repos*" OR Web.uri_path="*/orgs/*/repos*")
  by Web.src Web.dest_host Web.uri_path Web.http_method Web.http_user_agent
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    http_user_agent="Bun/*" OR http_user_agent="bun/*", 95,
    match(http_user_agent,"(?i)node|javascript"), 85,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime src dest_host uri_path http_method http_user_agent risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Python spawning Bun runtime | 90 | Bun is a JavaScript runtime; Python processes have no legitimate reason to spawn it; observed exclusively in Shai-Hulud/Miasma worm execution |
| Python/Bun fetching oven-sh/bun from GitHub | 90 | Matches exact Hades wave Bun runtime download pattern |
| Python spawning curl/wget to GitHub | 80 | Python rarely needs to shell out to download tools from GitHub at startup; strong anomaly signal |
| New `setup.pth`/`install.pth` file in site-packages | 80 | These non-standard .pth filenames match the Hades campaign artifact naming pattern |
| Bun executing `_index.js` | 95 | Exact Hades payload execution path; near-certain indicator |
| Bun executing script in /tmp or Temp | 85 | Consistent with downloaded and executed payload; high confidence |
| GitHub repo creation POST from Bun user-agent | 95 | Exact Shai-Hulud exfiltration pattern; Bun user-agent creating GitHub repos indicates active credential exfiltration |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| TeamPCP (UNC6780) | [Wiz — Mini Shai-Hulud TanStack](https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised), [Microsoft — Miasma Red Hat npm (2026-06-02)](https://www.microsoft.com/en-us/security/blog/2026/06/02/preinstall-persistence-inside-red-hat-npm-miasma-credential-stealing-campaign/) |
| Shai-Hulud / Miasma Worm Campaign | [BleepingComputer — Hades PyPI wave](https://www.bleepingcomputer.com/news/security/new-shai-hulud-attack-trojanizes-19-science-focused-pypi-packages/), [Socket.dev — Hades wave analysis](https://socket.dev/blog/shai-hulud-descends-to-hades-miasma-pypi-wave) |

## References

- [BleepingComputer — New Shai-Hulud attack trojanizes 19 science-focused PyPI packages](https://www.bleepingcomputer.com/news/security/new-shai-hulud-attack-trojanizes-19-science-focused-pypi-packages/)
- [Socket.dev — Shai-Hulud Descends to Hades: Miasma Worm Campaign Spreads with New PyPI Wave](https://socket.dev/blog/shai-hulud-descends-to-hades-miasma-pypi-wave)
- [StepSecurity — The Hades Campaign: Graph ML PyPI Packages](https://www.stepsecurity.io/blog/the-hades-campaign-pypi-packages)
- [The Hacker News — Hades PyPI Attack](https://thehackernews.com/2026/06/hades-pypi-attack-19-packages-poisoned.html)
- [MITRE ATT&CK — T1059.006: Command and Scripting Interpreter: Python](https://attack.mitre.org/techniques/T1059/006/)
- [MITRE ATT&CK — T1546: Event Triggered Execution](https://attack.mitre.org/techniques/T1546/)
- [MITRE ATT&CK — T1195.001: Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/001/)
