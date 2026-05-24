# Laravel-Lang Composer Tag-Rewrite Supply Chain Credential Stealer

## Description

Detects artifacts and behaviors associated with the May 2026 supply chain compromise of four `laravel-lang` Composer packages (`laravel-lang/lang`, `laravel-lang/attributes`, `laravel-lang/http-statuses`, `laravel-lang/actions`). An attacker used a **Composer tag-rewrite** technique — pointing historical Packagist version tags to commits in a malicious fork — to inject a 15-module PHP credential stealer that executes automatically via Composer's `autoload.files` mechanism on every PHP request. On Windows hosts the stealer drops `DebugChromium.exe` to bypass Chrome v127+ App-Bound Encryption. All harvested credentials (cloud keys, CI/CD tokens, SSH keys, browser passwords, crypto wallets) are AES-256 encrypted and exfiltrated to `flipboxstudio[.]info/exfil`.

False positives for `DebugChromium.exe` are expected to be zero — this filename has no legitimate association with Google Chrome or Chromium. PHP spawning shell interpreters may generate false positives in legitimate build/deploy pipelines; tune by exclusion list.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Supply Chain Compromise: Compromise Software Dependencies and Development Tools |
| Technique ID | T1195.001 |
| Secondary Tactic | Collection |
| Secondary Tactic ID | TA0009 |
| Secondary Technique | Credentials from Password Stores: Credentials from Web Browsers |
| Secondary Technique ID | T1555.003 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Delivery |
| Actions on Objectives |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name="DebugChromium.exe"
by Processes.dest Processes.user Processes.parent_process_name Processes.process_name
   Processes.process Processes.process_id Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    1=1, 95)
| where risk_score >= 95
| table firstTime lastTime dest user parent_process_name process_name process_path process risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| `DebugChromium.exe` process observed | 95 | No legitimate software uses this filename; exclusively associated with the Laravel-Lang supply chain Chrome credential bypass payload |
| Network traffic to `flipboxstudio.info` | 95 | Confirmed C2 and exfiltration endpoint; no legitimate use |
| PHP process spawning `wscript.exe`, `cscript.exe`, or `powershell.exe` | 85 | Indicates Composer autoloader executing malicious VBS/PowerShell launchers |
| File creation under `<TEMP>/.laravel_locale/` | 90 | Stealer-specific staging directory on Linux/macOS |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown (Laravel-Lang supply chain actor, May 2026) | [Aikido Security](https://www.aikido.dev/blog/supply-chain-attack-targets-laravel-lang-packages-with-credential-stealer), [StepSecurity](https://www.stepsecurity.io/blog/laravel-lang-supply-chain-attack), [BleepingComputer](https://www.bleepingcomputer.com/news/security/laravel-lang-packages-hijacked-to-deploy-credential-stealing-malware/) |

## References

- [Aikido Security — Supply Chain Attack Targets Laravel-Lang Packages (May 2026)](https://www.aikido.dev/blog/supply-chain-attack-targets-laravel-lang-packages-with-credential-stealer)
- [StepSecurity — Laravel-Lang Composer Tag-Rewrite Attack (May 2026)](https://www.stepsecurity.io/blog/laravel-lang-supply-chain-attack)
- [Mend — Laravel-Lang Composer Tag-Rewrite Supply-Chain Attack](https://www.mend.io/blog/laravel-lang-composer-tag-rewrite-supply-chain-attack)
- [Snyk — Laravel-Lang Supply Chain Advisory](https://snyk.io/blog/laravel-lang-supply-chain-advisory/)
- [MITRE ATT&CK T1195.001 — Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/001/)
- [MITRE ATT&CK T1555.003 — Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003/)
