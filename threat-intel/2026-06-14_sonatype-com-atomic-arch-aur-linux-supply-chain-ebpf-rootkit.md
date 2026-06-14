---
scraped_at: "2026-06-14T00:00:00Z"
source_url: https://www.sonatype.com/blog/atomic-arch-npm-campaign-adds-malicious-dependency
report_type: threat-intel
severity: high
title: "Atomic Arch: 400–1,500+ Arch Linux AUR Packages Backdoored via Malicious npm Dependency Delivering Rust Credential Stealer and eBPF Rootkit"
---

## 1. IOCs

### File Hashes

| Indicator | Type | Context |
|-----------|------|---------|
| `6144d433f8a0316869877b5f834c801251bbb936e5f1577c5680878c7443c98b` | SHA256 | ELF binary `deps` (Rust-compiled, stripped) embedded in atomic-lockfile@1.4.2 at path `src/hooks/deps`; primary credential-stealing and eBPF rootkit installer payload; Sonatype ID: Sonatype-2026-003775 |

### Malicious npm / Bun Packages

| Package Name | Version | Publisher Account | Registry |
|---|---|---|---|
| atomic-lockfile | 1.4.2 | herbsobering | npm |
| js-digest | (multiple) | herbsobering | npm |
| lockfile-js | (multiple) | (campaign-linked) | npm |

### Attacker-Controlled Accounts (npm / AUR)

| Account | Platform | Role |
|---------|----------|------|
| herbsobering | npm | Published atomic-lockfile and js-digest malicious packages |
| krisztinavarga | AUR / npm | AUR orphan adopter — claimed abandoned packages in Wave 1 |
| franziskaweber | AUR / npm | AUR orphan adopter — claimed abandoned packages in Wave 1 |
| tobiaswesterburg | AUR / npm | AUR orphan adopter — claimed abandoned packages in Wave 1 |
| ellenmyklebust | AUR / npm | AUR orphan adopter — claimed abandoned packages in Wave 1 |
| custodiatovar | bun | Wave 2 bun-registry credential publisher |
| veramagalhaes | bun | Wave 2 bun-registry credential publisher |

### C2 and Exfiltration

| Indicator | Type | Context |
|-----------|------|---------|
| Tor onion service (specific address not publicly confirmed) | C2 | Collected credentials sent via POST /api/agent over a local SOCKS-style loopback proxy routing to onion C2; specific address not released in public sources as of 2026-06-14 |
| temp.sh | Exfiltration relay | Legitimate file-upload service abused for secondary file exfiltration via POST /upload; content uploaded includes SSH keys, browser credential databases, and cloud credential files |

### Host Indicators

| Indicator | Context |
|-----------|---------|
| File path: `<npm_module>/src/hooks/deps` | Malicious ELF binary planted inside atomic-lockfile node module directory; executed via npm preinstall lifecycle hook |
| `/sys/fs/bpf/` — unfamiliar BPF map names | eBPF rootkit registers kernel programs that hide the `deps` process and its network sockets from `ps`, `htop`, `lsof`, `ss` |
| `/var/log/pacman.log` — `npm install atomic-lockfile` or `npm install js-digest` | AUR helper (yay, paru, pikaur, aurutils, trizen) invokes npm install during PKGBUILD execution; this logs into pacman.log |
| `makepkg` spawning `npm install` or `bun install` | Legitimate AUR build process, but anomalous when installing atomic-lockfile or js-digest; expected parent: makepkg or yay/paru |

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Initial Access | T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Attackers claimed ownership of 400–1,500+ orphaned AUR packages through AUR's standard adoption process; modified PKGBUILD scripts to inject `npm install atomic-lockfile` (or `js-digest`) during build, pulling in malicious credential-stealing payload |
| Execution | T1059.004 | Command and Scripting Interpreter: Unix Shell | PKGBUILD preinstall hook executes `./src/hooks/deps` (the Rust ELF) when npm install atomic-lockfile completes; the shell's PATH is used to locate the binary |
| Execution | T1059.007 | Command and Scripting Interpreter: JavaScript | Malicious npm preinstall lifecycle hook defined in package.json executes `./src/hooks/deps`; triggered automatically by npm during install without user confirmation |
| Defense Evasion | T1014 | Rootkit | eBPF program loaded at runtime hides the `deps` process and its network sockets from userland monitoring tools (`ps`, `top`, `htop`, `lsof`, `ss`, `netstat`); BPF maps persist in `/sys/fs/bpf/` |
| Defense Evasion | T1036.005 | Masquerading: Match Legitimate Name or Location | npm package names (atomic-lockfile, js-digest, lockfile-js) closely resemble legitimate utility packages to evade manual review of PKGBUILD dependencies |
| Credential Access | T1552.001 | Unsecured Credentials: Credentials In Files | Rust stealer harvests SSH private keys, browser stored credentials (Chrome/Firefox/Brave session cookies and saved passwords), GitHub tokens, npm auth tokens, Slack/Discord local session files, HashiCorp Vault tokens, and cloud credential files (~/.aws/credentials, ~/.config/gcloud/, ~/.azure/) |
| Credential Access | T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | Browser credential databases parsed and exfiltrated; targets Chromium/Firefox profile directories |
| Exfiltration | T1048 | Exfiltration Over Alternative Protocol | Exfiltration via two channels: (1) collected credentials POSTed to Tor onion C2 via local SOCKS proxy; (2) file contents uploaded to temp.sh via HTTP POST |
| Exfiltration | T1090.003 | Proxy: Multi-hop Proxy | C2 communication routes through a local loopback SOCKS proxy that connects to the Tor network, providing anonymization and preventing direct C2 IP attribution |
| Persistence | T1543 | Create or Modify System Process | On privileged hosts (root or sudo-accessible), eBPF programs persist across process restarts; BPF maps remain in `/sys/fs/bpf/` filesystem across reboots when pinned |

---

## 3. Malware & Tools

| Name | Type | Notes |
|------|------|-------|
| Atomic Arch Rust Stealer (`deps`) | Infostealer (ELF, Rust) | SHA256: `6144d433f8a0316869877b5f834c801251bbb936e5f1577c5680878c7443c98b`; stripped binary; async state machine architecture; credential harvesting from browsers, Electron apps, developer tools, and local secret stores |
| Atomic Arch eBPF Rootkit | Kernel rootkit (eBPF) | Loaded by `deps` binary on privileged hosts; registers BPF programs to hide the stealer process and its network sockets from userland process monitors; BPF maps pinned to `/sys/fs/bpf/`; mimics kernel thread appearance |
| atomic-lockfile@1.4.2 | Malicious npm package | CVSS 8.7; Sonatype-2026-003775; contains preinstall hook triggering `deps` ELF; published by herbsobering account |

---

## 4. Threat Actor / Campaign Attribution

**Campaign Name:** Atomic Arch (named by Sonatype)

Attribution remains unconfirmed as of 2026-06-14. The campaign is distinguished by operational sophistication: systematic adoption of dormant/orphaned AUR packages through legitimate AUR governance processes (avoiding detection by the AUR maintainer team), a two-wave expansion from ~400 to ~1,500 packages over 48 hours, use of Tor for C2 anonymization, and eBPF rootkit capability suggesting developer familiarity with Linux kernel internals.

**Targeting profile:** Arch Linux users and developers who install AUR packages — a demographic with elevated access to developer secrets, cloud credentials, SSH keys, and code-signing tokens. The campaign is consistent with supply chain actors motivated by credential theft for downstream access broker operations or CI/CD pipeline compromise.

**Wave 1 (June 9–11, 2026):** Accounts krisztinavarga, franziskaweber, tobiaswesterburg, ellenmyklebust adopted orphaned AUR packages and modified PKGBUILDs to pull `atomic-lockfile` or `lockfile-js`. First detected June 11, 2026.

**Wave 2 (June 12, 2026):** Attacker expanded to new AUR packages; added `js-digest` (bun registry) as alternative delivery vehicle via accounts custodiatovar and veramagalhaes; community detection tools (lenucksi/aur-malware-check, jasonherald/atomic-arch-check) published same day.

---

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.parent_process_name IN ("makepkg","yay","paru","pikaur","trizen","aurutils","aura")
  AND Processes.process_name IN ("npm","node","bun")
  AND Processes.process IN ("*install*","*i *")
by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| where match(process, "(?i)(atomic.lockfile|js.digest|lockfile.js)")
| eval risk_score=90
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.parent_process_name IN ("npm","node","bun")
  AND Processes.process_name="deps"
  AND Processes.process IN ("*/src/hooks/deps*","*node_modules*")
by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where Filesystem.file_path IN ("*/src/hooks/deps","*/.local/share/*","*/node_modules/atomic-lockfile/*","*/node_modules/js-digest/*","*/node_modules/lockfile-js/*")
  AND Filesystem.action="created"
by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(file_path, "(?i)(atomic.lockfile|js.digest|lockfile.js|src/hooks/deps)"), 90,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime dest user file_path file_name process_name risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.parent_process_name IN ("npm","node","bun","makepkg","yay","paru")
  AND Processes.process_name IN ("curl","wget","python3","python")
  AND Processes.process IN ("*temp.sh*","*upload*")
by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=75
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

---

## 6. Executive Summary

On June 11, 2026, Sonatype researchers disclosed **Atomic Arch**, a large-scale Arch Linux AUR supply chain attack in which threat actors systematically adopted orphaned AUR packages and modified their PKGBUILD build scripts to inject a malicious npm dependency (`atomic-lockfile@1.4.2`, `js-digest`, or `lockfile-js`) during package installation. When AUR users installed or upgraded affected packages using helpers such as `yay`, `paru`, or `pikaur`, the poisoned PKGBUILD executed `npm install atomic-lockfile`, which then triggered a preinstall lifecycle hook that executed the bundled Rust-compiled ELF binary `src/hooks/deps`.

The `deps` binary is a comprehensive Linux credential stealer targeting SSH private keys, browser saved credentials and session cookies (Chromium, Firefox, Brave), GitHub and npm authentication tokens, Slack and Discord local session files, HashiCorp Vault tokens, and cloud provider credential files (AWS, GCP, Azure). On privileged hosts, the binary also installs an **eBPF rootkit** that hides its own process and network sockets from userland monitoring tools (`ps`, `top`, `htop`, `lsof`, `ss`), severely hampering live-response investigation. Collected data is exfiltrated to a Tor onion C2 via a local SOCKS proxy (POST /api/agent) and files are separately uploaded to temp.sh.

**Wave 1** (June 9–11) compromised ~400 packages across AUR orphan adoptions by accounts krisztinavarga, franziskaweber, tobiaswesterburg, and ellenmyklebust. **Wave 2** (June 12) expanded to ~1,500 packages and added `js-digest` via bun registry accounts custodiatovar and veramagalhaes as an alternative delivery path.

**Affected users:** Any Arch Linux or Arch-based distribution user (Manjaro, EndeavourOS, Garuda, etc.) who installed or upgraded AUR packages via AUR helpers after June 9, 2026 should audit their `/var/log/pacman.log` for installations involving `atomic-lockfile`, `js-digest`, or `lockfile-js`. Community detection scripts are available at [lenucksi/aur-malware-check](https://github.com/lenucksi/aur-malware-check) and [jasonherald/atomic-arch-check](https://github.com/jasonherald/atomic-arch-check). Treat any affected host as fully compromised: rotate all credentials harvested from the host, including SSH keys, cloud credentials, GitHub/npm tokens, and browser-stored passwords.

---

## References

- [Sonatype — Atomic Arch: npm Campaign Adds Malicious Dependency](https://www.sonatype.com/blog/atomic-arch-npm-campaign-adds-malicious-dependency)
- [The Hacker News — Over 400 Arch Linux AUR Packages Hijacked to Deploy Infostealer and eBPF Rootkit](https://thehackernews.com/2026/06/over-400-arch-linux-aur-packages.html)
- [GitHub — lenucksi/aur-malware-check: Detection tools for the June 2026 atomic-lockfile AUR supply-chain attack](https://github.com/lenucksi/aur-malware-check)
- [GitHub — jasonherald/atomic-arch-check](https://github.com/jasonherald/atomic-arch-check)
- [StepSecurity — 400+ AUR Packages Hijacked: What the "Atomic Arch" Campaign Means for Supply-Chain Security](https://www.stepsecurity.io/blog/400-aur-packages-hijacked-atomic-arch-campaign)
- [SafeDep — Atomic Arch Campaign Threat Intelligence](https://safedep.io/ti/campaigns/atomic-arch/)
- [The CyberSec Guru — Atomic Arch: 900+ AUR Packages Backdoored with eBPF Rootkit](https://thecybersecguru.com/news/atomic-arch-aur-supply-chain-attack-ebpf-rootkit/)
- [OSV.dev — MAL-2026-2528](https://osv.dev/vulnerability/MAL-2026-2528)
- [MITRE ATT&CK — T1195.002 Supply Chain Compromise: Compromise Software Supply Chain](https://attack.mitre.org/techniques/T1195/002/)
- [MITRE ATT&CK — T1014 Rootkit](https://attack.mitre.org/techniques/T1014/)
