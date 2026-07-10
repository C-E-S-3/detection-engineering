---
scraped_at: "2026-07-10T08:50:00Z"
source_url: "https://www.bleepingcomputer.com/news/security/injective-sdk-on-npm-infected-with-cryptocurrency-wallet-stealer/"
report_type: threat-intel
severity: high
title: "Injective SDK npm Supply Chain Compromise: @injectivelabs/sdk-ts v1.20.21 Steals Cryptocurrency Wallet Keys via Legitimate Endpoint Exfiltration"
---

## 1. IOCs

### Package Indicators

| Type | Indicator | Context |
|------|-----------|---------|
| npm package | `@injectivelabs/sdk-ts` version `1.20.21` | MALICIOUS — compromised version published after GitHub repo access; exfiltrates wallet private keys and mnemonic seed phrases; ~50,000 weekly downloads |

### No External Malicious Network IOCs

The attack deliberately routes exfiltrated data through Injective Labs' own legitimate public infrastructure API endpoint to evade network-layer detection. No attacker-controlled external domain or IP was disclosed by Socket, Ox Security, or StepSecurity. Any detection requires behavioral/SAST/package-level controls rather than network blocking.

### No File Hashes Published

Specific SHA256 hashes for the malicious package payload were not publicly released in the BleepingComputer coverage. Verification should be done via npm package registry diff or the advisories from Socket, Ox Security, or StepSecurity.

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|--------------|----------------|-------|
| Initial Access | TA0001 / T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Attackers compromised the Injective Labs GitHub repository and published a malicious version of the official sdk-ts npm package |
| Credential Access | TA0006 / T1552 | Unsecured Credentials | Malicious npm package silently collects cryptocurrency wallet private keys and BIP-39 mnemonic seed phrases from applications at runtime |
| Exfiltration | TA0010 / T1567 | Exfiltration Over Web Service | Stolen wallet keys exfiltrated via HTTP POST to Injective Labs' own legitimate public API endpoint — blends into normal application traffic and evades network blocklists |
| Defense Evasion | TA0005 / T1036 | Masquerading | Using the target company's own legitimate infrastructure endpoint for exfiltration makes traffic indistinguishable from normal SDK usage at the network layer |

---

## 3. Malware & Tools

| Item | Type | Notes |
|------|------|-------|
| Injective wallet stealer (embedded in sdk-ts 1.20.21) | Supply chain payload | JavaScript; silently reads wallet private keys and mnemonic phrases from application context; exfiltrates via POST to legitimate Injective API endpoint; discovered by Socket, Ox Security, and StepSecurity |

---

## 4. Threat Actor / Campaign Attribution

- **Attribution:** Unknown threat actor with GitHub repository access to Injective Labs
- **Discovery:** Independently flagged by Socket, Ox Security (AppSec), and StepSecurity on or around July 9, 2026
- **Victim scope:** Any developer or end user of applications consuming `@injectivelabs/sdk-ts@1.20.21` — cryptocurrency wallets, trading bots, DEX frontends, DeFi applications, and payment tools built on the Injective Protocol ecosystem
- **Probable motivation:** Cryptocurrency theft (wallet private key/seed phrase collection for immediate drain of associated wallets)
- **Pattern overlap:** Follows well-established pattern of cryptocurrency SDK supply chain attacks (cf. Contagious Interview npm compromises, XZ-utils, polyfill.io)

---

## 5. Splunk Detection Searches

```spl
| comment "Detect execution of malicious @injectivelabs/sdk-ts supply chain payload via Node.js process"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name IN ("node","node.exe","nodejs","bun","bun.exe","deno","deno.exe")
    AND (Processes.process="*injectivelabs*" OR Processes.process="*sdk-ts*")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=80
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| comment "Hunt for npm install of compromised Injective SDK version in CI/CD pipeline logs or npm audit output"
index=* sourcetype IN ("ci_logs","npm_logs","jenkins","github_actions","gitlab_ci")
    ("@injectivelabs/sdk-ts" AND "1.20.21")
| stats count min(_time) as firstTime max(_time) as lastTime
    values(host) as affected_hosts
    by sourcetype
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime sourcetype affected_hosts risk_score
```

```spl
| comment "Detect unusual outbound HTTP POST from Node.js processes to DeFi/blockchain API endpoints after npm install (supply chain behavioral pattern)"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.app IN ("node","nodejs","node.exe")
    AND All_Traffic.action="allowed"
    AND All_Traffic.dest_port IN ("443","80")
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_ip All_Traffic.dest_port
     All_Traffic.app All_Traffic.bytes_out
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| where bytes_out > 1000
| eval risk_score=case(
    like(dest,"*injective*"), 70,
    1=1, 50)
| where risk_score >= 50
| table firstTime lastTime src dest dest_port app bytes_out risk_score
```

---

## 6. Executive Summary

An unknown threat actor compromised the official GitHub repository of Injective Labs and published a malicious version (`1.20.21`) of the `@injectivelabs/sdk-ts` npm package — the primary TypeScript SDK for Injective Protocol with approximately 50,000 weekly downloads. The malicious package silently collects cryptocurrency wallet private keys and BIP-39 mnemonic seed phrases from any application that uses the SDK, then exfiltrates them via HTTP POST to Injective Labs' own legitimate public API endpoint.

The exfiltration-via-legitimate-infrastructure tactic is a notable evasion improvement over typical supply chain attacks: because the data is sent to Injective's own API endpoint that SDK-using applications are expected to contact, network-layer monitoring and C2 blocklists will not fire. Compromise can only be detected through package version pinning, SAST/SCA scanning during CI/CD, or behavioral analysis (e.g., unexpected POST volumes or payload shapes to normally-read-only API endpoints).

Any developer or application that installed or used `@injectivelabs/sdk-ts@1.20.21` should treat all wallet private keys and mnemonic phrases accessible to those applications as compromised and transfer assets to new wallets immediately. The compromise was independently discovered and disclosed by Socket, Ox Security, and StepSecurity.

**Severity: High.** The attack surface is the software supply chain, affecting developers and end users across the Injective DeFi ecosystem. Private key theft results in immediate irreversible loss of cryptocurrency assets. The evasion technique (exfiltration via legitimate vendor endpoint) will become a template for future attacks.

---

## References

- [BleepingComputer: Injective SDK on npm infected with cryptocurrency wallet stealer (July 9, 2026)](https://www.bleepingcomputer.com/news/security/injective-sdk-on-npm-infected-with-cryptocurrency-wallet-stealer/)
- [Socket Security: Supply chain research](https://socket.dev)
- [MITRE ATT&CK T1195.002 — Supply Chain Compromise: Compromise Software Supply Chain](https://attack.mitre.org/techniques/T1195/002/)
- [MITRE ATT&CK T1552 — Unsecured Credentials](https://attack.mitre.org/techniques/T1552/)
- [MITRE ATT&CK T1567 — Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567/)
- [npm: @injectivelabs/sdk-ts](https://www.npmjs.com/package/@injectivelabs/sdk-ts)
