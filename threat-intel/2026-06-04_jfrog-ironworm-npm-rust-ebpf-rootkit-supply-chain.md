---
scraped_at: 2026-06-05T05:00:00Z
source_url: https://research.jfrog.com/post/iron-worm-shai-hulud-rustier-cousin/
report_type: threat-intel
severity: high
title: "IronWorm: Rust-Built npm Supply Chain Worm Deploys eBPF Rootkit and Tor C2 Across 37 Packages — JFrog Security Research June 2026"
---

# IronWorm: Rust-Built npm Supply Chain Worm Deploys eBPF Rootkit and Tor C2 Across 37 Packages

JFrog Security Research identified IronWorm on June 3, 2026 — a highly sophisticated Rust-written supply chain worm distributed through at least 37 compromised npm packages. IronWorm is a direct evolutionary successor to the Shai-Hulud worm family and represents a significant escalation: it deploys an eBPF kernel rootkit to hide its processes and network connections from standard monitoring tools, communicates over Tor for attribution-resistant C2, and self-propagates by minting new npm publish credentials via stolen OIDC tokens. The campaign originated from the compromised `asteroiddao` npm account and was amplified through npm's Trusted Publishing workflow.

## 1. IOCs

### Compromised npm Account

| Indicator | Type | Context |
|-----------|------|---------|
| `asteroiddao` | npm account | Compromised account from which 43 malicious package versions were published; root of propagation |

### Affected Package (Example — Confirmed Malicious Version)

| Package | Version | Context |
|---------|---------|---------|
| `weavedb-sdk` | `0.45.3` | Contains 976KB Linux ELF dropper executed via `preinstall` script in package.json; confirmed malicious version |

Note: JFrog identified 37 total affected packages across nine organizations. The full package list is published in the JFrog Security Research report; only examples confirmed in public reporting are listed here.

### C2 Infrastructure

| Indicator | Type | Context |
|-----------|------|---------|
| Tor hidden service | `.onion` (undisclosed) | IronWorm beacons to `/api/agent` endpoint on a Tor hidden service; Tor client embedded in the Rust binary |
| `temp.sh` | Fallback exfil | Legitimate file-sharing service used as a fallback exfiltration channel when Tor C2 is unavailable |

No C2 .onion addresses have been publicly disclosed as of June 5, 2026.

### File Artifacts

| Indicator | Type | Context |
|-----------|------|---------|
| 976 KB Linux ELF binary in `tools/` directory | ELF dropper | Rust-compiled binary embedded in malicious npm packages; executed automatically during `npm install` via `preinstall` hook |

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique | ID | Description |
|--------|-----------|----|-------------|
| Initial Access | Supply Chain Compromise: Compromise Software Dependencies and Development Tools | T1195.001 | Threat actor compromised the `asteroiddao` npm account and published 43 malicious versions across 37 packages containing a hidden Rust ELF binary executed via `preinstall` lifecycle hook |
| Execution | Command and Scripting Interpreter: Unix Shell | T1059.004 | `preinstall` hook in package.json triggers `sh -c` to execute the embedded Rust ELF binary during package installation; fires automatically with no user interaction beyond `npm install` |
| Execution | Native API | T1106 | Rust binary uses native system calls directly to load eBPF programs into the Linux kernel without requiring external tools |
| Persistence | Create or Modify System Process | T1543 | eBPF kernel rootkit loaded into the Linux kernel provides persistent process and network connection hiding that survives across sessions |
| Defense Evasion | Rootkit | T1014 | eBPF rootkit intercepts system events and hides IronWorm processes and network connections from `ps`, `top`, `ss`, `netstat`, and similar monitoring tools; anti-debugging logic terminates inspector processes |
| Defense Evasion | Obfuscated Files or Information | T1027 | Rust ELF binary uses source-level obfuscation and is compiled without debug symbols; eBPF programs are embedded as opaque bytecode |
| Credential Access | Steal Application Access Token | T1528 | Malware harvests 86 environment variables and 20 credential files including OpenAI API keys, AWS credentials, Anthropic API keys, npm auth tokens, SSH private keys, Vault configuration files, and Exodus cryptocurrency wallet files |
| Credential Access | Credentials from Password Stores | T1555 | Targets local credential files (SSH keys, `.npmrc`, cloud provider CLI config files) for direct credential harvesting |
| Collection | Data from Local System | T1005 | Collects cloud identity credentials, CI/CD pipeline tokens, and developer secrets from both the filesystem and 86 environment variables |
| Exfiltration | Exfiltration Over C2 Channel | T1041 | Exfiltrates harvested credentials to a Tor hidden service via the `/api/agent` HTTP endpoint; uses `temp.sh` as a fallback exfiltration channel |
| Lateral Movement | Supply Chain Propagation (self-replicating) | T1195.001 | IronWorm mints short-lived npm publish credentials from stolen OIDC tokens via npm's Trusted Publishing workflow; every CI/CD run on an infected package becomes a new publisher, trojanizing downstream packages owned by compromised accounts |
| Resource Development | Compromise Accounts | T1586.003 | Compromised the `asteroiddao` npm account (and expanded to additional accounts via harvested tokens) as the seed propagation vehicle |

## 3. Malware & Tools

### IronWorm

- **Type:** Self-propagating supply chain worm / credential stealer / rootkit dropper
- **Written in:** Rust (compiled ELF, Linux x86-64)
- **Size:** 976 KB embedded binary in npm packages `tools/` directory
- **Delivery:** `preinstall` lifecycle hook in `package.json` executing `sh -c [binary_path]`
- **C2 Protocol:** HTTPS to Tor hidden service (`/api/agent`); `temp.sh` fallback
- **Rootkit:** eBPF kernel-level rootkit loaded to hide processes and network connections from standard monitoring utilities
- **Anti-debugging:** Actively terminates processes that attempt to inspect the malware
- **Propagation:** Steals npm OIDC tokens and uses Trusted Publishing to mint publish credentials; poisons new packages owned by the victim account, spreading to their downstream consumers
- **Credential targets:** 86 environment variables + 20 credential files across OpenAI, AWS, Anthropic, npm, SSH, HashiCorp Vault, Exodus wallet

### Relationship to Prior Supply Chain Worms

| Worm | Time | Notes |
|------|------|-------|
| Mini Shai-Hulud | May 2026 | TeamPCP wave 2; Python/JS-based; Session Protocol exfil; OIDC token theft |
| Shai-Hulud | September 2025 | Original npm worm; marked start of high-consequence npm threat landscape |
| IronWorm | June 2026 | Rust-based evolution; adds eBPF rootkit, Tor C2, expanded credential targets |

IronWorm is described by JFrog as "Shai-Hulud's rustier cousin," indicating evolutionary lineage with the Shai-Hulud/TeamPCP worm family but potentially distinct threat actor or toolkit vendor.

## 4. Threat Actor / Campaign Attribution

| Actor | Confidence | Notes |
|-------|-----------|-------|
| Unknown (possibly TeamPCP-adjacent) | Low | JFrog's "rustier cousin" framing suggests evolutionary connection to the Shai-Hulud/TeamPCP supply chain worm family, but IronWorm's Rust+eBPF+Tor architecture represents a significant capability uplift not previously attributed to TeamPCP. Attribution unclear as of June 5, 2026. |

**Targeting:** Primarily Web3 and DeFi developers (initial victim is `asteroiddao`, a blockchain project), but IronWorm's credential targeting extends broadly to any developer environment running the affected packages — including CI/CD systems accessing OpenAI, AWS, and Anthropic APIs.

**Campaign Scale:** At least 37 unique npm packages across nine organizations; combined monthly downloads of the affected packages exceed 32,000; 57 malicious code changes pushed across affected repositories before discovery.

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where (Processes.process_name IN ("npm", "node", "npm.cmd")
  OR Processes.parent_process_name IN ("npm", "node"))
  AND Processes.process_name IN ("sh", "bash")
  AND (Processes.process="*preinstall*" OR Processes.process="*tools/*" OR Processes.process="*.elf*")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=80
| where risk_score >= 80
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.parent_process_name IN ("npm", "node", "npm.cmd")
  AND Processes.process_name NOT IN ("npm", "node", "node.exe", "sh", "bash", "python", "python3",
    "tar", "unzip", "cp", "mv", "mkdir", "chmod", "tsc", "gyp", "make", "cmake")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    process_name IN ("curl", "wget", "nc"), 85,
    process_name IN ("id", "whoami", "uname"), 90,
    match(process, "/tmp/.*"), 85,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.app IN ("tor", "tcp") AND All_Traffic.dest_port IN (9050, 9001, 9030)
  AND All_Traffic.src_category="endpoint"
by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=75
| where risk_score >= 75
| table firstTime lastTime src dest dest_port app risk_score
```

## 6. Executive Summary

IronWorm is a Rust-built npm supply chain worm discovered by JFrog on June 3, 2026. Starting from a compromised `asteroiddao` npm account, the attacker published malicious versions of at least 37 npm packages embedding a 976KB Rust ELF binary executed automatically via `preinstall` hooks during `npm install`. Once executed, the binary:

1. Loads an eBPF kernel rootkit that hides its processes and network connections from standard monitoring tools
2. Harvests credentials from 86 environment variables and 20 credential files (AWS, OpenAI, Anthropic, npm tokens, SSH keys, Vault configs, crypto wallets)
3. Exfiltrates to a Tor hidden service (`/api/agent`) with `temp.sh` as a fallback
4. Self-propagates by minting new npm publish credentials via stolen OIDC tokens, poisoning packages owned by the victim account

This represents a significant escalation in supply chain worm sophistication over the Shai-Hulud/TeamPCP lineage: the addition of a kernel-level eBPF rootkit, Tor-based C2, and expanded credential targeting across AI services (OpenAI, Anthropic) signals a mature, well-resourced threat actor. Developers should audit all recent `npm install` operations across CI/CD pipelines, rotate all credentials and tokens in environments where affected packages may have been installed, and enable package signature verification with `npm audit`.

## References

- [JFrog Security Research — IronWorm: Shai-Hulud's Rustier Cousin](https://research.jfrog.com/post/iron-worm-shai-hulud-rustier-cousin/)
- [BleepingComputer — New IronWorm Malware Hits 36 Packages in npm Supply-Chain Attack](https://www.bleepingcomputer.com/news/security/new-ironworm-malware-hits-36-packages-in-npm-supply-chain-attack/)
- [OX Security — IronWorm Supply Chain Malware Hits npm](https://www.ox.security/blog/ironworm-supply-chain-malware-hits-npm/)
- [Dark Reading — Rust-Written IronWorm Hits NPM Supply Chain](https://www.darkreading.com/cyberattacks-data-breaches/rust-written-ironworm-npm-supply-chain)
- [SafeDep TI — IronWorm Campaign](https://safedep.io/ti/campaigns/ironworm/)
- [MITRE ATT&CK — T1195.001: Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/001/)
- [MITRE ATT&CK — T1014: Rootkit](https://attack.mitre.org/techniques/T1014/)
