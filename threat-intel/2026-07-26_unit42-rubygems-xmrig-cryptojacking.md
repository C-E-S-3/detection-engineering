---
title: "RubyGems Supply Chain Cryptojacking Campaign — 136 Malicious Gems, XMRig v6.22.2, SSH Worm"
source: https://raw.githubusercontent.com/PaloAltoNetworks/Unit42-timely-threat-intel/main/2026-07-22-RubyGems-Cryptojacking-Campaign.txt
source_display: "Palo Alto Networks Unit 42 — Timely Threat Intel (July 22, 2026)"
date_published: 2026-07-22
date_added: 2026-07-26
tags:
  - cryptojacking
  - supply-chain
  - rubygems
  - xmrig
  - t1195.001
  - t1496
  - t1021.004
  - impact
  - initial_access
actors:
  - Prvaz12_mars
  - monib110
  - Andrey78
ioc_types:
  - domain
  - monero_wallet
mitre_techniques:
  - T1195.001
  - T1496
  - T1021.004
---

## Executive Summary

Palo Alto Networks Unit 42 identified a RubyGems supply chain cryptojacking campaign in which three threat actors — Prvaz12_mars, monib110, and Andrey78 — published 136 malicious gems to rubygems.org accumulating approximately 14,000 downloads before takedown. Each gem ships an XMRig v6.22.2 miner binary embedded in the gem's native extension directory. The miner connects to Monero mining pools using wallet addresses hardcoded per actor. A worm component propagates via SSH: it reads `~/.ssh/known_hosts` and `~/.ssh/config`, attempts passwordless key-based authentication to known hosts, and copies the malicious gem to newly compromised systems where it self-installs.

The gems impersonated legitimate popular packages (color, faker, json, rake, rspec variants, and others) using typosquatting and name confusion. Malicious code executed during `gem install` via a poisoned `extconf.rb` or postinstall hook, making the attack effective even when the installed gem was never `require`d.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access, Impact |
| Tactic ID | TA0001, TA0040 |
| Technique | Supply Chain Compromise: Compromise Software Dependencies and Development Tools |
| Technique ID | T1195.001 |
| Secondary Technique | Resource Hijacking |
| Secondary Technique ID | T1496 |
| Tertiary Technique | Remote Services: SSH (worm propagation) |
| Tertiary Technique ID | T1021.004 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Delivery (malicious package published to rubygems.org) |
| Exploitation (postinstall hook execution during `gem install`) |
| Actions on Objectives (XMRig CPU/GPU mining; SSH worm propagation) |

## Threat Actors

| Actor | Notes |
|-------|-------|
| Prvaz12_mars | RubyGems account; primary campaign operator; hardcodes Monero wallet 47vT2mcSzKPP2fEnZJ5QaVaF2fEEmvhxZHi26Hn9XixhY6tqNTtpXE8XXhG7Uoj6eta9a9HWmhssuS712s271jFf5vPngnn |
| monib110 | Secondary actor; second Monero wallet 8Aao1ANqXNeAfreezPgN3HYm5o96Jo8qEACDBZ1aZjjp5sRoP8HGcJwF97GEfP5GXofm9Y5vRMsWrWpxNNmKcQWh9qnqXZ2 |
| Andrey78 | Tertiary actor; overlapping gem namespace squatting |

## Indicators of Compromise

### Monero Mining Pools (Domains)

| Domain | Context |
|--------|---------|
| pool.moneroocean[.]stream | Primary Monero mining pool endpoint; XMRig pool argument |
| p2pool[.]io | Decentralized P2Pool Monero mining pool; used as fallback |
| pool.supportxmr[.]com | SupportXMR mining pool; secondary pool argument |
| de.monero.herominers[.]com | HeroMiners German Monero pool node; tertiary pool |

### Monero Wallets

| Wallet | Actor |
|--------|-------|
| 47vT2mcSzKPP2fEnZJ5QaVaF2fEEmvhxZHi26Hn9XixhY6tqNTtpXE8XXhG7Uoj6eta9a9HWmhssuS712s271jFf5vPngnn | Prvaz12_mars |
| 8Aao1ANqXNeAfreezPgN3HYm5o96Jo8qEACDBZ1aZjjp5sRoP8HGcJwF97GEfP5GXofm9Y5vRMsWrWpxNNmKcQWh9qnqXZ2 | monib110 |

## TTPs and Behavior

- **Delivery**: Malicious gems published under typosquatted or name-confused identifiers on rubygems.org
- **Execution trigger**: `extconf.rb` postinstall hook executes shell command at `gem install` time; no `require` needed
- **Payload**: XMRig v6.22.2 ELF/PE binary extracted from gem's `ext/` directory and spawned as background process
- **Persistence**: Cron job or systemd unit written to re-launch miner on reboot; process masquerades as `kworker` or `systemd-udevd`
- **SSH worm**: Reads `~/.ssh/known_hosts` and SSH config files; attempts `ssh -i` key auth to known hosts; `scp`s gem and re-runs install
- **Pool rotation**: Falls back across four Monero pools if primary is unreachable
- **Obfuscation**: XMRig process name spoofed to common kernel thread names; cron entry uses absolute path to avoid `PATH`-based detection

## Detection Opportunities

This campaign is covered by the existing **[Unauthorized GPU Cryptominer Execution](../detections/impact/gpu_cryptomining_unauthorized_miner_execution.md)** detection (T1496), which detects XMRig process execution and Monero pool connection arguments.

Additional detection opportunities specific to supply chain delivery:

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name IN ("gem", "bundle")
    Processes.process IN ("*extconf*", "*postinstall*", "*xmrig*", "*kworker*")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process, "(?i)xmrig"), 95,
    match(process, "(?i)moneroocean|supportxmr|herominers|p2pool"), 90,
    match(process, "(?i)extconf|postinstall"), 50)
| where risk_score >= 50
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

DNS detection for Monero pool lookups:

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Resolution.DNS
  where DNS.query IN ("pool.moneroocean.stream", "p2pool.io", "pool.supportxmr.com",
                      "de.monero.herominers.com")
  by DNS.src DNS.query DNS.record_type
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src query record_type risk_score
```

## References

- [Unit 42 Timely Threat Intel — RubyGems Cryptojacking Campaign (2026-07-22)](https://raw.githubusercontent.com/PaloAltoNetworks/Unit42-timely-threat-intel/main/2026-07-22-RubyGems-Cryptojacking-Campaign.txt)
- [MITRE ATT&CK — T1195.001: Supply Chain Compromise: Compromise Software Dependencies](https://attack.mitre.org/techniques/T1195/001/)
- [MITRE ATT&CK — T1496: Resource Hijacking](https://attack.mitre.org/techniques/T1496/)
- [MITRE ATT&CK — T1021.004: Remote Services: SSH](https://attack.mitre.org/techniques/T1021/004/)
