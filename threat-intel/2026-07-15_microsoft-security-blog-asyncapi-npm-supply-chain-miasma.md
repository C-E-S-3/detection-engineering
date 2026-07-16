---
scraped_at: 2026-07-15T00:00:00Z
source_url: https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/
report_type: threat-intel
severity: high
title: "AsyncAPI npm Supply Chain Compromise: Miasma Worm Import-Time Payload Delivery via Weaponized GitHub Actions CI/CD"
---

## 1. IOCs

### Hashes

| Hash (SHA256) | Description |
|---------------|-------------|
| `d425e4583cc6185d41e95c45eda00550045a5d1919b9a012236a4520d009dbd7` | Malicious `@asyncapi/specs` dist/setup.js — MiasmStealer v6.4 import-time payload |
| `9b2e65db653ca8575c9b10eefb9a80c6006404812c2ec212bf5675e3c690233b` | Malicious `@asyncapi/specs` dist/setup.js — alternate sample |
| `bfaeb987faa6de2b5a5eb63b1233d055215b09b0349a9394f2175fd7cdf385e4` | Malicious `@asyncapi/specs` dist/setup.js — alternate sample |
| `082d733db0687dcd768104972b065d4b58cb1e6043688c6c20fa3702337f36ab` | Malicious `@asyncapi/specs` dist/setup.js — alternate sample |
| `34014776d3d3ff11bc4439b02fd7ac0f02a887eb3a052eeafff236e2f6db8ad1` | Malicious `@asyncapi/specs` dist/setup.js — alternate sample |
| `8351d251cf0b5a0bd82242deaa0a14e3e1394418d55c0f4259dac4303b79fc0c` | Malicious `@asyncapi/specs` dist/setup.js — alternate sample |
| `b9993a8ad0518849416798cf29668256ccb96598fc4423501ccab5312812653a` | Malicious `@asyncapi/specs` dist/setup.js — alternate sample |
| `b270bdf8e2274ea1af0a6eed74d8f10e5fe61012d6cc226a43cc7cc7fd9f6292` | Malicious `@asyncapi/specs` dist/setup.js — alternate sample |
| `6e78713b75bd34828d49896176627f7face7aa9036cd874f2e02d9f23a9a9c71` | Malicious `@asyncapi/specs` dist/setup.js — alternate sample |
| `24b9ee242f21a73b55f7bb3297eafb33c60840907386b542ed79fc6b72365168` | Malicious `@asyncapi/specs` dist/setup.js — alternate sample |

### IP Addresses

| IP | Description |
|----|-------------|
| `85.137.53[.]71` | MiasmStealer v6.4 C2 exfiltration endpoint; ports 8080, 8081, 8091; receives stolen credentials, environment variables, and cloud access tokens |

### Malicious npm Packages

| Package | Malicious Version(s) | Description |
|---------|---------------------|-------------|
| `@asyncapi/specs` | 6.11.2-alpha.1, 6.11.2 | Root poisoned package; dist/setup.js executes MiasmStealer at import time |
| `@asyncapi/generator` | 3.3.1 | Depends on poisoned @asyncapi/specs; CI/CD toolchains that install generator pull the payload |
| `@asyncapi/generator-components` | 0.7.1 | Depends on poisoned @asyncapi/specs |
| `@asyncapi/generator-helpers` | 1.1.1 | Depends on poisoned @asyncapi/specs |

### GitHub Actions

| Reference | Description |
|-----------|-------------|
| `m-red-team/asyncapi-release-helper@v1` | Malicious GitHub Actions workflow injected into AsyncAPI release automation; triggers on `release` event; installs poisoned @asyncapi/specs version and exfiltrates `GITHUB_TOKEN`, npm publish tokens, and environment secrets |

## 2. TTPs

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Initial Access | T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Attacker (`m-red-team` GitHub account) injected malicious release workflow into AsyncAPI organization; weaponized CI/CD to publish poisoned @asyncapi/specs 6.11.2 to npm registry |
| Execution | T1059.004 | Command and Script Interpreter: Unix Shell | Import-time payload in dist/setup.js executes shell commands via `child_process.execSync` when any downstream package imports @asyncapi/specs |
| Credential Access | T1528 | Steal Application Access Token | Payload harvests `GITHUB_TOKEN`, npm publish tokens, AWS credentials, and service account tokens from CI/CD environment variables |
| Credential Access | T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | On developer workstations that import the package locally, payload also targets browser-stored credentials |
| Defense Evasion | T1027 | Obfuscated Files or Information | Payload in dist/setup.js uses multi-layer base64 and hex encoding; disguised as legitimate initialization module within the package's normal dist output directory |
| Collection | T1005 | Data from Local System | Collects environment variables, SSH keys from ~/.ssh/, cloud credentials from ~/.aws/credentials, ~/.config/gcloud/, and ~/.kube/config |
| Command and Control | T1041 | Exfiltration Over C2 Channel | Stolen data compressed and POSTed to 85.137.53[.]71 on ports 8080/8081/8091 via HTTPS |
| Resource Development | T1586.003 | Compromise Accounts: Cloud Accounts | `m-red-team` GitHub account used to inject malicious workflow; account history suggests it is a compromised legitimate developer account repurposed by Miasma operators |

## 3. Malware & Tools

**MiasmStealer v6.4** (also tracked as **Miasma worm**) is a JavaScript-based credential stealer distributed as a poisoned npm package payload. The July 2026 campaign represents a significant evolution from prior Miasma activity (June 2026: AI coding agent workspace poisoning via Claude Code, Cursor, VS Code, and Gemini CLI config files) to a new attack surface: **import-time payload delivery** within legitimate npm packages.

**Key distinction from postinstall supply chain attacks:**

Traditional npm supply chain attacks (Glassworm, node-ipc, Mastra, Atomic Arch) execute malicious code during `npm install` via the `postinstall` hook. This is increasingly detected by lockfile auditing tools (Snyk, Socket.dev, Phylum) and CI/CD policies that block postinstall hooks.

Miasma v6.4 bypasses this by embedding payload code in the package's compiled output (`dist/setup.js`) that runs at **import time** — when application code calls `require('@asyncapi/specs')` or `import from '@asyncapi/specs'`. This means:
- The malicious code does not run during `npm install`; it runs when the application or toolchain actually imports the module
- Standard postinstall hook auditing does not detect it
- In CI/CD pipelines, this typically means execution during the `build`, `test`, or `release` steps rather than during dependency installation

**Infection vector — GitHub Actions CI/CD weaponization:**

The `m-red-team/asyncapi-release-helper@v1` GitHub Actions workflow was injected into AsyncAPI's release automation. When triggered on a release event, the workflow installs the poisoned @asyncapi/specs version and calls the generator toolchain, causing the import-time payload to execute in the privileged CI/CD context where `GITHUB_TOKEN` and npm publish tokens are available as environment secrets.

**Payload behavior:**

1. On execution, the payload checks for common CI/CD environment variables (`GITHUB_TOKEN`, `CI`, `GITHUB_ACTIONS`, `NPM_TOKEN`, `AWS_ACCESS_KEY_ID`, etc.)
2. If in a CI/CD context: prioritizes harvesting automation tokens (GITHUB_TOKEN, npm tokens, cloud credentials)
3. If on a developer workstation: targets SSH keys, cloud credential files (~/.aws, ~/.kube, ~/.config/gcloud), and browser credential stores
4. Compressed payload transmitted via HTTPS POST to `85.137.53[.]71` on ports 8080, 8081, or 8091 (with failover across the three ports)

**Affected scope:**

Any project with `@asyncapi/generator`, `@asyncapi/generator-components`, or `@asyncapi/generator-helpers` in its dependency tree was exposed during the window when versions 6.11.2-alpha.1 and 6.11.2 of `@asyncapi/specs` were live on the npm registry (July 11–14, 2026). Microsoft Defender for Endpoint telemetry identified approximately 1,200 affected CI/CD pipelines globally before takedown.

The AsyncAPI project patched all affected packages and published an incident report. npm registry pulled the malicious versions.

## 4. Threat Actor / Campaign Attribution

**Miasma** is an unattributed threat actor running a persistent npm supply chain campaign active since at least June 2026. Prior Miasma activity targeted AI coding agent configuration files (Claude Code `CLAUDE.md`, Cursor `.cursorrules`, VS Code `settings.json`, Gemini CLI config) via workspace poisoning. The July 2026 AsyncAPI campaign represents a tactical pivot to import-time delivery.

The `m-red-team` GitHub organization used to host the malicious release workflow appears to be a compromised legitimate developer account or a dedicated infrastructure account established for this campaign. No clear geographic or national attribution has been made.

Victimology across both Miasma campaigns heavily overlaps with software development organizations and developer toolchain maintainers, consistent with financially motivated credential harvesting for downstream access brokerage.

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.dest="85.137.53.71"
  OR All_Traffic.dest_ip="85.137.53.71"
by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src dest dest_port app risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.dest_port IN (8080, 8081, 8091)
  AND (All_Traffic.app="node" OR All_Traffic.process_name="node" OR All_Traffic.process_name="node.js")
by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.process_name
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=60
| where risk_score >= 60
| table firstTime lastTime src dest dest_port process_name risk_score
```

```spl
index=* sourcetype IN ("github_actions", "ci_cd_audit", "npm_audit")
(action="workflow_run" OR action="package_install" OR action="package_publish")
(workflow="asyncapi-release-helper" OR package_name IN ("@asyncapi/specs","@asyncapi/generator","@asyncapi/generator-components","@asyncapi/generator-helpers")
 AND (package_version="6.11.2" OR package_version="6.11.2-alpha.1" OR package_version="3.3.1" OR package_version="0.7.1" OR package_version="1.1.1"))
| stats count min(_time) as firstTime max(_time) as lastTime by actor package_name package_version workflow
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime actor package_name package_version workflow risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name IN ("node", "node.js")
  AND Processes.parent_process_name IN ("actions-runner", "runner.Worker", "runner.Listener", "gh", "npm", "npx")
  AND (Processes.process="*asyncapi*" OR Processes.process="*setup.js*")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=75
| where risk_score >= 75
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

## 6. Executive Summary

On July 15, 2026, Microsoft Security Blog disclosed a supply chain compromise of the AsyncAPI npm ecosystem in which the threat actor behind the Miasma worm (m-red-team GitHub account) poisoned `@asyncapi/specs` versions 6.11.2-alpha.1 and 6.11.2 with the MiasmStealer v6.4 import-time payload. Unlike prior npm supply chain attacks that trigger during `npm install` via postinstall hooks, the Miasma payload executes when application code imports the module — bypassing postinstall-hook auditing controls. The malicious `m-red-team/asyncapi-release-helper@v1` GitHub Actions workflow was injected into AsyncAPI release automation, causing CI/CD pipelines to execute the payload in privileged contexts where `GITHUB_TOKEN` and npm publish tokens are available as environment secrets. Stolen credentials are transmitted to C2 `85.137.53[.]71` on ports 8080–8091. An estimated 1,200 CI/CD pipelines were affected before the malicious npm package versions were pulled. Organizations using `@asyncapi/generator`, `@asyncapi/generator-components`, or `@asyncapi/generator-helpers` should audit for the poisoned @asyncapi/specs dependency versions, rotate any GitHub, npm, cloud, and service account tokens used in CI/CD pipelines that ran between July 11–14, 2026, and monitor for outbound connections to `85.137.53[.]71`.

## References

- [Microsoft Security Blog — Unpacking AsyncAPI npm Supply Chain Compromise: Import-Time Payload Delivery (2026-07-15)](https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/)
- [MITRE ATT&CK T1195.002 — Supply Chain Compromise: Compromise Software Supply Chain](https://attack.mitre.org/techniques/T1195/002/)
- [MITRE ATT&CK T1528 — Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)
- [MITRE ATT&CK T1027 — Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
