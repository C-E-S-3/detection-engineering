# Miasma npm Import-Time Payload Delivery via Poisoned AsyncAPI Packages

## Description

Detects MiasmStealer payload execution delivered via import-time code in poisoned npm packages (`@asyncapi/specs` versions 6.11.2-alpha.1 and 6.11.2). Unlike traditional postinstall-hook supply chain attacks, this payload executes when application code imports the module — bypassing postinstall hook auditing controls. The primary infection vector was the `m-red-team/asyncapi-release-helper@v1` GitHub Actions workflow injected into AsyncAPI release automation, causing privileged CI/CD environments to execute the payload and expose `GITHUB_TOKEN`, npm tokens, and cloud credentials to C2 at `85.137.53[.]71` (ports 8080, 8081, 8091).

**What this detects:**
- Outbound connections from Node.js processes to the Miasma C2 IP (`85.137.53.71`) on characteristic ports
- Node.js processes spawned from CI/CD runner contexts with asyncapi/setup.js in the command line
- Installation of known-poisoned @asyncapi/specs package versions in CI/CD audit logs

**Expected false positives:** Legitimate traffic to `85.137.53.71` is not expected. The port 8080 connection search may produce low-rate noise from Node.js applications making HTTP calls; filter by destination IP to reduce FP volume. CI/CD process searches require accurate parent process name normalization for your runner environment.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Supply Chain Compromise: Compromise Software Supply Chain |
| Technique ID | T1195.002 |
| Secondary Tactic | Credential Access |
| Secondary Technique | Steal Application Access Token (T1528); Credentials from Web Browsers (T1555.003) |
| Secondary Tactic | Defense Evasion |
| Secondary Technique | Obfuscated Files or Information (T1027) |

## Lockheed Martin Kill Chain

| Phase | Relevance |
|-------|-----------|
| Delivery | Malicious npm package published to public registry; pulled by CI/CD pipelines and developer workstations as a legitimate dependency |
| Exploitation | Import-time payload executes during build/test/release steps when application code loads the poisoned package |
| Actions on Objectives | Credential exfiltration of CI/CD secrets, cloud tokens, SSH keys to attacker-controlled C2 |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where (All_Traffic.dest="85.137.53.71" OR All_Traffic.dest_ip="85.137.53.71")
by All_Traffic.src All_Traffic.dest All_Traffic.dest_ip All_Traffic.dest_port
   All_Traffic.app All_Traffic.process_name
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src dest dest_ip dest_port app process_name risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name IN ("node", "node.js")
  AND Processes.parent_process_name IN (
    "actions-runner", "runner.Worker", "runner.Listener",
    "gh", "npm", "npx", "yarn"
  )
  AND (Processes.process="*asyncapi*" OR Processes.process="*setup.js*")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=80
| where risk_score >= 80
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score
```

```spl
index=* sourcetype IN ("github_actions", "ci_cd_audit", "npm_audit")
(package_name IN ("@asyncapi/specs","@asyncapi/generator","@asyncapi/generator-components","@asyncapi/generator-helpers")
 AND package_version IN ("6.11.2","6.11.2-alpha.1","3.3.1","0.7.1","1.1.1"))
OR workflow="asyncapi-release-helper" OR repo_owner="m-red-team"
| stats count min(_time) as firstTime max(_time) as lastTime
    by actor package_name package_version workflow repo_owner
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime actor package_name package_version workflow repo_owner risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Network connection to `85.137.53.71` | 95 | Known Miasma C2; no legitimate use expected |
| Node.js spawned from CI/CD runner referencing asyncapi/setup.js | 80 | Highly specific to the known attack pattern |
| Poisoned package version installed (audit log match) | 90 | Exact version match to known malicious releases |

## Associated Threat Actors

| Actor | Malware/Tool | Notes |
|-------|-------------|-------|
| Miasma (unattributed) | MiasmStealer v6.4 | Active npm supply chain campaign; prior June 2026 activity involved AI coding agent config file workspace poisoning; July 2026 pivot to import-time delivery via AsyncAPI ecosystem |

## References

- [Microsoft Security Blog — Unpacking AsyncAPI npm Supply Chain Compromise: Import-Time Payload Delivery (2026-07-15)](https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/)
- [MITRE ATT&CK T1195.002 — Supply Chain Compromise: Compromise Software Supply Chain](https://attack.mitre.org/techniques/T1195/002/)
- [MITRE ATT&CK T1528 — Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)
- [npm security advisory — @asyncapi/specs 6.11.2 / 6.11.2-alpha.1](https://www.npmjs.com/advisories)
