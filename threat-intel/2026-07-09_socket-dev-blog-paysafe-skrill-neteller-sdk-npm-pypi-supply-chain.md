---
scraped_at: "2026-07-09T00:00:00Z"
source_url: "https://socket.dev/blog/npm-pypi-campaign-typosquats-popular-secure-payment-apps"
report_type: threat-intel
severity: high
title: "Fake Paysafe, Skrill, and Neteller SDK Packages on npm and PyPI Steal Developer Credentials"
---

## 1. IOCs

### Domains
| Indicator | Type | Context |
|-----------|------|---------|
| `caliber-spinner-finishing[.]ngrok-free.dev` | C2 / Exfiltration | Ngrok tunnel endpoint; attacker-controlled exfiltration server; infrastructure overlap with prior NjRAT C2 campaigns |

### Malicious Package Names

**npm (13 packages, versions 1.0.0–1.0.3):**
- `paysafe-checkout`
- `paysafe-vault`
- `paysafe-api`
- `paysafe-node`
- `paysafe-payments`
- `paysafe-sdk`
- `paysafe-kyc`
- `paysafe-js`
- `paysafe-cards`
- `paysafe-fraud`
- `skrill`
- `skrill-sdk`
- `skrill-payments`

**PyPI (4 packages, version 1.0.0):**
- `paysafe-sdk`
- `paysafe-payments`
- `paysafe-api`
- `paysafe-kyc`

### Obfuscation Artifacts
- XOR key: `SGf6lmbr7GHUg99Z6R2U3g==` (hardcoded in payload; 17 subtracted per character post-decode to resolve C2)

### Data Stolen
- `PAYSAFE_API_KEY`
- `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`
- `GITHUB_TOKEN`
- `NPM_TOKEN`
- Hostname, username
- Any environment variable matching token/password/API key patterns

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|---------------|-------|
| Initial Access | T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | 17 typosquatted npm/PyPI packages published simultaneously impersonating Paysafe, Skrill, and Neteller SDKs |
| Execution | T1059.007 | Command and Scripting Interpreter: JavaScript | npm postinstall script executes credential harvesting payload; fires only if `PAYSAFE_API_KEY` present and fake SDK invoked |
| Execution | T1059.006 | Command and Scripting Interpreter: Python | PyPI `__init__.py` auto-executes on `import` without any triggering condition |
| Defense Evasion | T1027 | Obfuscated Files or Information | XOR obfuscation of C2 destination; per-package unique hashes defeat signature scanning |
| Credential Access | T1552.001 | Unsecured Credentials: Credentials In Files | Harvests environment variables for AWS, GitHub, npm, and Paysafe API keys |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | Credentials exfiltrated to `caliber-spinner-finishing[.]ngrok-free.dev` |

---

## 3. Malware & Tools

| Name | Type | Description |
|------|------|-------------|
| Paysafe/Skrill typosquatters | Supply chain credential stealer | 17 packages implement full API surface returning fake success responses while silently harvesting developer credentials; PyPI variant fires automatically on import; npm variant fires only when activated with a Paysafe API key |

**Behavioral note:** The packages are API-mimicking — they accept calls and return realistic-looking success responses, allowing the compromise to remain undetected across CI/CD pipeline test runs.

---

## 4. Threat Actor / Campaign Attribution

- **Attribution:** No named APT group; financially motivated operator
- **Infrastructure:** NjRAT C2 overlap noted on the Ngrok exfiltration endpoint
- **Pattern:** Simultaneous multi-registry publication (npm + PyPI) with per-package unique hashes is consistent with automated supply chain toolkits; similar to prior Sapphire Sleet and TeamPCP campaigns but no direct link confirmed
- **Targeting:** Fintech/payment platform developers and CI/CD pipelines integrating Paysafe/Skrill/Neteller payment processing

---

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.process_name="node" OR Processes.process_name="npm" OR Processes.process_name="python*" OR Processes.process_name="pip*")
    AND (Processes.process IN ("*paysafe-checkout*","*paysafe-vault*","*paysafe-api*","*paysafe-node*","*paysafe-payments*","*paysafe-sdk*","*paysafe-kyc*","*paysafe-js*","*paysafe-cards*","*paysafe-fraud*","*skrill*","*skrill-sdk*","*skrill-payments*"))
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime dest user process_name process risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_host="caliber-spinner-finishing.ngrok-free.dev"
  by All_Traffic.src_ip All_Traffic.dest_host All_Traffic.dest_port All_Traffic.process
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src_ip dest_host dest_port process risk_score
```

```spl
index=* sourcetype IN ("npm_audit","sast_results","dependency_check","osquery")
(package_name IN ("paysafe-checkout","paysafe-vault","paysafe-api","paysafe-node","paysafe-payments","paysafe-sdk","paysafe-kyc","paysafe-js","paysafe-cards","paysafe-fraud","skrill","skrill-sdk","skrill-payments"))
| eval risk_score=90
| table _time, host, user, package_name, package_version, risk_score
```

---

## 6. Executive Summary

On July 7, 2026, Socket Security's AI scanner flagged 17 malicious packages published simultaneously to npm and PyPI within minutes of each other. The packages typosquat the legitimate Paysafe, Skrill, and Neteller payment SDK namespaces, implementing realistic API surfaces that return fake success responses while silently exfiltrating developer credentials.

The npm variants harvest credentials only when a `PAYSAFE_API_KEY` environment variable is present and the SDK is actively invoked, making detection harder in CI/CD pipelines that run ephemeral test containers. The PyPI variants are more aggressive, executing automatically on `import`. All packages exfiltrate to an Ngrok tunnel endpoint with demonstrated NjRAT C2 infrastructure overlap.

Developers and CI/CD pipelines that installed any of the 17 packages should immediately rotate all AWS credentials, GitHub tokens, npm tokens, and Paysafe API keys accessible from the affected environment.

---

## References

- [Socket Security — Original Research](https://socket.dev/blog/npm-pypi-campaign-typosquats-popular-secure-payment-apps)
- [BleepingComputer — Fake Paysafe, Skrill SDKs on NPM and PyPI steal credentials](https://www.bleepingcomputer.com/news/security/fake-paysafe-skrill-sdks-on-npm-and-pypi-steal-credentials/)
- [MITRE ATT&CK T1195.002 — Supply Chain: Software](https://attack.mitre.org/techniques/T1195/002/)
