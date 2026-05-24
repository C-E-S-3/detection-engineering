---
scraped_at: 2026-05-24T00:00:00Z
source_url: https://www.aikido.dev/blog/supply-chain-attack-targets-laravel-lang-packages-with-credential-stealer
report_type: threat-intel
severity: high
title: "Laravel-Lang Composer Tag-Rewrite Supply Chain Attack: 233 Versions Poisoned with Cross-Platform Credential Stealer"
---

# Laravel-Lang Composer Tag-Rewrite Supply Chain Attack: 233 Versions Poisoned with Cross-Platform Credential Stealer

On May 22–23, 2026, attackers executed a novel Composer **tag-rewrite supply chain attack** against four widely-used Laravel localization packages published under the `laravel-lang` namespace on Packagist. By pointing Git tags to commits in an attacker-controlled fork, the adversary injected a 5,900-line cross-platform PHP credential stealer into 233+ poisoned versions of the packages. The stealer collects cloud keys, Kubernetes secrets, CI/CD tokens, SSH keys, browser credentials (including Chrome v127+ App-Bound Encryption bypass via `DebugChromium.exe`), crypto wallets, and messaging tokens, then AES-256 encrypts and exfiltrates everything to the C2 endpoint `flipboxstudio[.]info/exfil`.

---

## 1. IOCs

### Domains

| Indicator | Description |
|-----------|-------------|
| `flipboxstudio[.]info` | Attacker-controlled C2 and exfiltration server; stealer downloads second-stage payload from this domain and POSTs encrypted stolen data to `/exfil` |

### File Artifacts

| Indicator | Description |
|-----------|-------------|
| `DebugChromium.exe` | Windows EXE dropped from base64-encoded payload within the malicious PHP helper; bypasses Chrome v127+ App-Bound Encryption to extract browser master decryption key |
| `src/helpers.php` | Malicious entry point injected into poisoned Composer tags; wired into Composer's `autoload.files`, executes on every PHP request |
| `<sys_get_temp_dir>/.laravel_locale/` | Staging directory created by the stealer on Linux/macOS for downloaded payloads |

### Affected Packages (Packagist / Composer)

| Package | Description |
|---------|-------------|
| `laravel-lang/lang` | Widely-used community translation package |
| `laravel-lang/attributes` | Attribute translation package |
| `laravel-lang/http-statuses` | HTTP status translation package |
| `laravel-lang/actions` | Action verb translation package |

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Initial Access | TA0001 | T1195.001 | Supply Chain Compromise: Compromise Software Dependencies — attacker rewrote historical Composer/Packagist tags to point to commits in a malicious fork, injecting code without touching official repos |
| Execution | TA0002 | T1059.004 | Command and Scripting Interpreter: Unix Shell — helpers.php runs shell commands on Linux/macOS targets to download and execute second-stage payloads |
| Execution | TA0002 | T1059.003 | Command and Scripting Interpreter: Windows Command Shell — .vbs launcher script and DebugChromium.exe dropped and executed on Windows targets |
| Collection | TA0009 | T1555.003 | Credentials from Password Stores: Credentials from Web Browsers — DebugChromium.exe bypasses Chrome v127+ App-Bound Encryption to extract saved browser credentials |
| Collection | TA0009 | T1552.001 | Unsecured Credentials: Credentials in Files — harvests .env files, cloud provider configs (AWS, GCP, Azure), Kubernetes kubeconfig, Vault/OpenBao tokens, SSH keys |
| Collection | TA0009 | T1552.004 | Unsecured Credentials: Private Keys — collects SSH private keys and crypto wallet key material |
| Collection | TA0009 | T1528 | Steal Application Access Token — harvests CI/CD tokens (GitHub Actions, GitLab, CircleCI), messaging tokens (Slack, Discord, Telegram) |
| Exfiltration | TA0010 | T1041 | Exfiltration Over C2 Channel — collected credentials AES-256 encrypted and POSTed to https://flipboxstudio[.]info/exfil |
| Defense Evasion | TA0005 | T1027 | Obfuscated Files or Information — DebugChromium.exe embedded as base64 in the PHP stealer; payload deletes itself post-execution |
| Defense Evasion | TA0005 | T1070.004 | Indicator Removal: File Deletion — stealer deletes itself from disk after exfiltration to limit forensic evidence |
| Persistence | TA0003 | T1546 | Event Triggered Execution — malicious code executes on every PHP request via Composer autoloader (autoload.files), achieving execution without explicit invocation |

---

## 3. Malware & Tools

### PHP Credential Stealer (helpers.php)
- **Size:** ~5,900 lines
- **Language:** PHP
- **Activation:** Composer autoload.files mechanism; runs on every PHP request after poisoned package installation
- **Modules (15 collector modules):**
  - Cloud credentials (AWS, GCP, Azure, DigitalOcean)
  - Kubernetes configs and in-cluster service account tokens
  - CI/CD tokens (GitHub Actions `GITHUB_TOKEN`, GitLab, CircleCI, Jenkins)
  - SSH keys and known_hosts
  - Browser credentials (via DebugChromium.exe on Windows)
  - Password manager vaults
  - Cryptocurrency wallet key material
  - Messaging platform tokens (Slack, Discord, Telegram)
  - Environment files (.env) and configuration files
- **Exfiltration:** AES-256 encryption → HTTPS POST to `https://flipboxstudio[.]info/exfil`
- **Cleanup:** Self-deletes from disk after exfiltration

### DebugChromium.exe (Windows)
- **Type:** Chrome credential extraction binary
- **Purpose:** Bypasses Chrome v127+ App-Bound Encryption to extract the browser master decryption key
- **Delivery:** Base64-decoded and dropped by helpers.php; executed via .vbs launcher script

---

## 4. Threat Actor / Campaign Attribution

| Attribute | Detail |
|-----------|--------|
| Actor | Unknown — unattributed supply chain threat actor |
| Targeting | PHP/Laravel developers and DevOps environments installing laravel-lang packages via Composer |
| Scale | 233+ poisoned package versions; 700+ GitHub repository tags rewritten |
| Attack Window | May 22–23, 2026; malicious tags published in rapid succession (seconds apart), indicating automation |
| Motivation | Credential theft at scale — CI/CD tokens, cloud keys, SSH material for downstream enterprise access |

Attribution has not been established. The automation of tag rewriting and the breadth of credential targets suggest a threat actor focused on large-scale developer credential theft, similar in profile to previous npm and PyPI supply chain actors.

---

## 5. Splunk Detection Searches

### Search 1 — Execution of DebugChromium.exe (Chrome credential bypass artifact)
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name="DebugChromium.exe"
by Processes.dest Processes.user Processes.parent_process_name Processes.process_name
   Processes.process Processes.process_id Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| where risk_score >= 95
| table firstTime lastTime dest user parent_process_name process_name process_path risk_score
```

### Search 2 — Network traffic to Laravel-Lang stealer C2 domain
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.dest_domain="flipboxstudio.info"
by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.dest_domain
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src_ip dest_ip dest_port dest_domain risk_score
```

### Search 3 — PHP or web application process spawning unexpected child processes (Composer autoloader abuse)
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.parent_process_name IN ("php","php-fpm","php-fpm8","php8.1","php8.2","php8.3","php.exe","artisan")
  AND Processes.process_name IN ("wscript.exe","cscript.exe","powershell.exe","cmd.exe",
                                  "bash","sh","curl","wget","python","python3")
by Processes.dest Processes.user Processes.parent_process_name Processes.process_name
   Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    Processes.process_name IN ("wscript.exe","cscript.exe","powershell.exe"), 85,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

### Search 4 — File creation in .laravel_locale staging directory (Linux/macOS stealer artifact)
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where Filesystem.file_path="*/.laravel_locale/*"
    OR Filesystem.file_name="DebugChromium.exe"
by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.action
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| where risk_score >= 90
| table firstTime lastTime dest user file_name file_path action risk_score
```

---

## 6. Executive Summary

A sophisticated supply chain attack compromised four `laravel-lang` Composer packages between May 22–23, 2026, using a novel **Composer tag-rewrite** technique: rather than committing malicious code to official repositories, the attacker pointed historical Git version tags to commits in a malicious fork they controlled. This evaded conventional source code auditing. Once installed via `composer install` or `composer update`, an injected `helpers.php` file auto-executes on every PHP request, running a 15-module credential stealer that targets cloud keys, CI/CD tokens, SSH keys, browser passwords, crypto wallets, and messaging tokens. On Windows, a base64-encoded `DebugChromium.exe` drops and executes to bypass Chrome v127+ App-Bound Encryption. All collected data is AES-256 encrypted and exfiltrated to `flipboxstudio[.]info/exfil`. Organizations using any `laravel-lang/*` packages should immediately audit `composer.lock` for affected versions, rotate all credentials that may have been exposed, and hunt for `DebugChromium.exe` execution and outbound connections to `flipboxstudio[.]info`.

---

## References

- [Aikido Security — Supply Chain Attack Targets Laravel-Lang Packages](https://www.aikido.dev/blog/supply-chain-attack-targets-laravel-lang-packages-with-credential-stealer)
- [StepSecurity — Laravel-Lang Supply Chain Attack](https://www.stepsecurity.io/blog/laravel-lang-supply-chain-attack)
- [Mend — Laravel-Lang Composer Tag-Rewrite Supply-Chain Attack](https://www.mend.io/blog/laravel-lang-composer-tag-rewrite-supply-chain-attack)
- [Snyk — Laravel-Lang Supply Chain Advisory](https://snyk.io/blog/laravel-lang-supply-chain-advisory/)
- [BleepingComputer — Laravel-Lang packages hijacked](https://www.bleepingcomputer.com/news/security/laravel-lang-packages-hijacked-to-deploy-credential-stealing-malware/)
- [The Hacker News — Laravel-Lang PHP Packages Compromised](https://thehackernews.com/2026/05/laravel-lang-php-packages-compromised.html)
- [Socket.dev — Laravel-Lang Compromise](https://socket.dev/blog/laravel-lang-compromise)
