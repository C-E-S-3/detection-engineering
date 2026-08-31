---
scraped_at: 2026-08-31T00:00:00Z
source_url: https://www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns
report_type: threat-intel
severity: high
title: "DPRK/UNC1069 Rust Crates Supply Chain Attack: arrayref, internment, append-only-vec"
---

# DPRK/UNC1069 Rust Crates Supply Chain Attack: arrayref, internment, append-only-vec

**Date Reported:** August 20–21, 2026  
**Source:** Wiz.io  
**Severity:** High  

## 1. IOCs

### IP Addresses
| Indicator | Type | Context |
|-----------|------|---------|
| 23.254.167.13 | IPv4 C2 | DPRK Rust crates C2 server; Hostwinds LLC AS54290; same /23 block (23.254.164.0/23) as prior DPRK campaigns; beacon path `/49890878` |

### Malicious Crates (crates.io)
| Package | Version | Published (UTC) | Live Duration |
|---------|---------|-----------------|---------------|
| arrayref | 0.3.10 | 2026-08-20 07:15 | ~86 min |
| internment | 0.8.7 | 2026-08-20 07:22 | ~97 min |
| append-only-vec | 0.1.9 | 2026-08-20 07:37 | ~107 min |

### Malicious Proc-Macro Packages Injected
| Package | Notes |
|---------|-------|
| proc-macro1 | Primary injected dependency |
| proc-macro-en | Alternate name, same cluster |
| aovine | Alternate name |
| arone | Alternate name |
| aronenao | Alternate name |
| tinymember | Alternate name |

## 2. TTPs

| Tactic | Technique | Sub-technique | Details |
|--------|-----------|---------------|---------|
| Initial Access | T1195 | T1195.001 — Compromise Software Supply Chain | Published malicious versions of popular Rust crates to crates.io |
| Execution | T1059 | — | Malicious proc-macro executes native code at `cargo build` time |
| Command & Control | T1071 | T1071.001 — Web Protocols | HTTPS beacon to 23.254.167.13 via path `/49890878` |
| Collection | T1005 | — | Exfiltration of source code, credentials, crypto wallet keys consistent with DPRK developer-targeting pattern |

**MITRE Tactic:** TA0001 (Initial Access), TA0002 (Execution), TA0011 (C2)  
**Kill Chain Phases:** Delivery, Exploitation, C2

## 3. Malware & Tools

**proc-macro1 (and six alternate names):** A malicious Rust procedural macro that executes as full native code at compile time. When any project that depends on the poisoned crates is built, the macro silently beacons to 23.254.167.13 and may exfiltrate build environment data or stage additional payloads. The threat is particularly high because `cargo build` runs proc-macros with the developer's full local permissions, including access to SSH keys, environment variables, and wallet files.

## 4. Threat Actor

**DPRK / UNC1069 / Sapphire Sleet**

| Attribute | Value |
|-----------|-------|
| MITRE Group | [G0032 — Lazarus Group](https://attack.mitre.org/groups/G0032/) |
| Sponsoring state | North Korea (DPRK) |
| Known aliases | UNC1069, Sapphire Sleet, BlueNoroff, TraderTraitor |
| Primary targets | Cryptocurrency developers, DeFi projects, FinTech |
| Infrastructure pattern | Hostwinds LLC AS54290; /23 subnet 23.254.164.0/23 reused across campaigns |

**Infrastructure overlap with previously tracked campaigns:**
- 23.254.167.216 — UNC1069 / axios npm (already in ip.csv)
- 23.254.164.92 — DPRK Mastra npm campaign (already in ip.csv)
- 23.254.167.13 — this campaign (new, added to ip.csv)

## 5. Splunk Detection Searches

### Detect download of known-malicious crate versions via proxy
```spl
index=* sourcetype IN ("proxy", "network_traffic", "bluecoat", "squid", "forcepoint")
(url="*crates.io/crates/arrayref/0.3.10*"
  OR url="*crates.io/crates/internment/0.8.7*"
  OR url="*crates.io/crates/append-only-vec/0.1.9*"
  OR url="*crates.io/crates/proc-macro1*"
  OR url="*crates.io/crates/proc-macro-en*"
  OR url="*crates.io/crates/aovine*"
  OR url="*crates.io/crates/arone*"
  OR url="*crates.io/crates/aronenao*"
  OR url="*crates.io/crates/tinymember*")
| table _time src dest url status
| sort -_time
```

### Detect C2 beacon to DPRK Rust crates infrastructure
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_ip="23.254.167.13"
  by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src_ip dest_ip dest_port app count risk_score
```

### Detect cargo/rustc process spawning network connections (Sysmon)
```spl
index=* sourcetype="xmlwineventlog" EventCode=3
  (Image="*\\cargo.exe" OR Image="*\\rustc.exe" OR Image="*/.cargo/bin/cargo" OR Image="*/rustc")
  DestinationIp!="127.0.0.1" DestinationIp!="::1"
  DestinationIp!="0.0.0.0"
| eval is_known_dprk=if(match(DestinationIp, "^23\.254\.(164|165|166|167)\."), "YES", "NO")
| eval risk_score=case(is_known_dprk="YES", 95, 1=1, 55)
| where risk_score >= 55
| table _time Computer User Image DestinationIp DestinationPort is_known_dprk risk_score
| sort -risk_score -_time
```

**Risk Score:** 95 (Critical) for known DPRK Hostwinds /23 IPs; 55 (Medium) for any cargo/rustc outbound network

## 6. Executive Summary

On August 20, 2026, DPRK-attributed threat actor UNC1069 (Sapphire Sleet) published malicious versions of three popular Rust crates — **arrayref@0.3.10**, **internment@0.8.7**, and **append-only-vec@0.1.9** — to crates.io. Each malicious version injected a dependency on `proc-macro1` (distributed under six alternate names), a malicious procedural macro that executes native code silently at compile time.

The attack is significant for two reasons. First, **arrayref alone has ~245 million all-time downloads** and is present in over 35% of Rust environments, making the potential blast radius extremely large. Second, Rust proc-macros run with the build user's full OS permissions — making this a reliable initial-access vector that bypasses most endpoint controls. The malicious versions were live for 86–107 minutes, long enough to be cached by registry mirrors worldwide.

The C2 infrastructure (23.254.167.13, Hostwinds LLC AS54290) falls in the same /23 subnet used by two other DPRK supply chain campaigns already tracked in this repository, confirming campaign continuity. Wiz.io rates the attribution as high confidence.

**Recommended actions:**
1. Audit all `Cargo.lock` files for any of the three poisoned crate versions or six malicious proc-macro names.
2. Block 23.254.167.13 and the broader 23.254.164.0/23 range at perimeter.
3. Alert on cargo/rustc processes making outbound network connections.
4. Rebuild any Rust projects that used these versions with a clean, pinned Cargo.lock.

## References

- https://www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns
- https://attack.mitre.org/techniques/T1195/001/
- https://attack.mitre.org/groups/G0032/
- https://www.cisa.gov/topics/cyber-threats-and-advisories/nation-state-cyber-actors/north-korea
