# Glassworm Blockchain-Based C2: Developer Tool Connections to Solana RPC Endpoints

## Description

Detects developer toolchain processes (node, npm, Python, pip) making outbound connections to Solana blockchain RPC API endpoints. The Glassworm botnet (active 2025–2026) used Solana blockchain transaction memo fields as an immutable, censorship-resistant dead drop for C2 server addresses — a novel technique specifically designed to survive conventional domain-seizure or sinkhole operations. The GlasswormRAT Chrome extension also retrieved C2 commands encoded in Solana transaction memos.

Legitimate developer workstations have no business reason for package managers or scripting runtimes (npm, pip, node, python) to connect directly to Solana RPC endpoints during normal operations. Web3 developers working on Solana DApps would use this legitimately, but the process ancestry context distinguishes those cases.

False positives: Dedicated Solana DApp developers; automated testing frameworks for blockchain applications. Tune with an allowlist of known Solana developer project directories or process command lines.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Command and Control |
| Tactic ID | TA0011 |
| Technique | Web Service |
| Technique ID | T1102 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Command & Control (C2) |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_hostname IN (
      "api.mainnet-beta.solana.com",
      "api.devnet.solana.com",
      "api.testnet.solana.com",
      "rpc.ankr.com",
      "solana-mainnet.rpc.extrnode.com",
      "mainnet.rpc.triton.one",
      "solana-rpc.publicnode.com")
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_hostname All_Traffic.dest_port
     All_Traffic.app All_Traffic.bytes_out
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(app,"(?i)(node|npm|pip|python|extensionHost)"), 80,
    match(app,"(?i)(chrome|chromium|msedge|brave)"), 55,
    1=1, 50)
| where risk_score >= 50
| table firstTime lastTime src dest dest_hostname dest_port app bytes_out risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest="164.92.88.210"
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95, note="Glassworm CrowdStrike sinkhole — infected host detected; immediate remediation required"
| table firstTime lastTime src dest dest_port app risk_score note
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| npm, pip, node, or extensionHost connecting to Solana RPC | 80 | High — package managers have no legitimate reason to contact blockchain infrastructure |
| Browser process connecting to Solana RPC | 55 | Suspicious in non-Web3 environments; GlasswormRAT Chrome extension uses this channel |
| Any non-browser process connecting to Solana RPC | 50 | Anomalous; warrants analyst review |
| Connection to 164.92.88.210 (Glassworm sinkhole) | 95 | Near-certain Glassworm infection confirmed by sinkhole beacon |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Glassworm | [CrowdStrike — Disrupting Glassworm (2026-05-26)](https://www.crowdstrike.com/en-us/blog/inside-crowdstrike-takedown-of-a-developer-targeting-botnet/), [Sonatype — Hijacked npm Packages Deliver Malware via Solana (2026)](https://www.sonatype.com/blog/hijacked-npm-packages-deliver-malware-via-solana-linked-to-glassworm) |

## References

- [CrowdStrike — Disrupting Glassworm: Inside CrowdStrike's Takedown of a Developer-Targeting Botnet (2026-05-26)](https://www.crowdstrike.com/en-us/blog/inside-crowdstrike-takedown-of-a-developer-targeting-botnet/)
- [Sonatype — Hijacked npm Packages Deliver Malware via Solana, Linked to Glassworm](https://www.sonatype.com/blog/hijacked-npm-packages-deliver-malware-via-solana-linked-to-glassworm)
- [Aikido — GlassWorm Chrome Extension RAT (Keylogger, Cookie Theft)](https://www.aikido.dev/blog/glassworm-chrome-extension-rat)
- [MITRE ATT&CK — T1102 Web Service](https://attack.mitre.org/techniques/T1102/)
