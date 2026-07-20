# SmartLoader Polygon Smart Contract C2 Dead-Drop Resolver

## Description

Detects SmartLoader's command-and-control mechanism in which the malware resolves its active C2 server address by calling `eth_call` against an attacker-controlled Polygon (MATIC) smart contract via public JSON-RPC endpoints. The contract address and function selector are hardcoded in the SmartLoader Lua stage; the contract's storage slot holds the current C2 IP address. Because the C2 address lives on-chain rather than in DNS, it cannot be sinkholed — the actor simply updates the contract state to redirect infected hosts to a new C2 server. Collected host data (browser credentials, API keys, crypto wallet material) is then exfiltrated to the resolved bare-IP C2 via multipart HTTP POST.

SmartLoader's use of the Polygon blockchain distinguishes it from other blockchain C2 techniques in the threat landscape:
- **EtherHiding** (Sandworm UAC-0145): Ethereum mainnet RPC endpoints (`cloudflare-eth.com`, `mainnet.infura.io`)
- **ViteVenom/PolinRider** (DPRK): TRON blockchain (`api.trongrid.io`) + Aptos/BSC fallbacks
- **SmartLoader** (FakeGit gang): Polygon/MATIC (`polygon.drpc.org`, `polygon-rpc.com`)

Polygon uses the same EVM-compatible JSON-RPC API as Ethereum (`eth_call`, `eth_getBalance`), so the HTTP request body is structurally identical. Differentiation is by the destination hostname.

Detection targets non-browser processes making HTTPS connections to Polygon JSON-RPC endpoints. Expected false positives: DeFi developers, Web3 dApp developers, Polygon-native application developers. Scope with asset group filters to exclude designated blockchain developer workstations.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Command and Control |
| Tactic ID | TA0011 |
| Technique | Web Service: Bidirectional Communication |
| Technique ID | T1102.002 |
| Secondary Technique | Dynamic Resolution (blockchain-based dead-drop) |
| Secondary Technique ID | T1568 |
| Tertiary Technique | Fallback Channels |
| Tertiary Technique ID | T1008 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Command & Control |

## Splunk Detection Queries

### Query 1: Non-Browser Process Connecting to Polygon JSON-RPC Endpoints

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.dest_host IN (
    "polygon.drpc.org",
    "polygon-rpc.com",
    "rpc-mainnet.matic.network",
    "matic-mainnet.chainstacklabs.com",
    "rpc.ankr.com",
    "polygon-mainnet.public.blastapi.io",
    "polygon.llamarpc.com",
    "polygon.meowrpc.com",
    "polygonapi.terminet.io",
    "polygon-mainnet.infura.io",
    "polygon-bor.publicnode.com",
    "api.polygonscan.com")
  AND NOT All_Traffic.app IN (
    "chrome", "firefox", "msedge", "brave", "safari",
    "chromium", "opera", "vivaldi", "iexplore")
by All_Traffic.src All_Traffic.dest All_Traffic.dest_host All_Traffic.dest_port
   All_Traffic.app All_Traffic.process_name
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_name, "(?i)lua\.exe|luajit\.exe|lua52|lua53|lua54|luajit"), 95,
    match(process_name, "(?i)powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32"), 90,
    match(process_name, "(?i)curl|wget|certutil|bitsadmin"), 80,
    match(process_name, "(?i)node|node\.exe|npm"), 75,
    match(process_name, "(?i)python|pip"), 70,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime src dest_host dest_port app process_name risk_score
```

### Query 2: DNS Query to Polygon RPC Providers from Endpoint

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Resolution.DNS
where DNS.query IN (
    "polygon.drpc.org",
    "polygon-rpc.com",
    "rpc-mainnet.matic.network",
    "matic-mainnet.chainstacklabs.com",
    "polygon-mainnet.public.blastapi.io",
    "polygon.llamarpc.com",
    "polygon.meowrpc.com",
    "polygon-mainnet.infura.io",
    "polygon-bor.publicnode.com")
by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=70
| table firstTime lastTime src query answer risk_score
```

### Query 3: Multipart POST from LOCALAPPDATA Binary to Bare IP (StealC Exfiltration)

```spl
index=proxy OR index=web
method="POST"
(src_path LIKE "%AppData/Local%"
 OR src_path LIKE "%LOCALAPPDATA%"
 OR src_binary LIKE "%AppData\\Local\\%")
NOT (dest_host="*.*.*" dest_host!="")
| rex field=dest "^(?P<dest_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$"
| where isnotnull(dest_ip)
| eval risk_score=85, note="POST to bare IP from LOCALAPPDATA binary — matches SmartLoader/StealC C2 exfil pattern"
| table _time src dest_ip uri_path status bytes_out risk_score note
```

### Query 4: Correlation — LuaJIT Execution Followed by Polygon RPC Connection (Same Host, 10min Window)

```spl
index=endpoint OR index=network
| eval event_type=case(
    (process_name IN ("lua.exe","luajit.exe","lua52.exe","luajit") AND parent_process_name IN ("node.exe","npm.cmd","python.exe","pip.exe")), "lua_exec",
    (dest_host IN ("polygon.drpc.org","polygon-rpc.com","rpc-mainnet.matic.network")), "polygon_c2",
    1=1, null())
| where isnotnull(event_type)
| eval bucket_time=floor(_time/600)*600
| stats values(event_type) as events dc(event_type) as event_types by host bucket_time
| where event_types >= 2 AND mvfind(events,"lua_exec") >= 0 AND mvfind(events,"polygon_c2") >= 0
| eval risk_score=98, note="SmartLoader confirmed: LuaJIT dropper + Polygon blockchain C2 on same host within 10 minutes"
| table bucket_time host events risk_score note
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| LuaJIT connecting to Polygon RPC + prior lua_exec event | 98 | SmartLoader confirmed; correlates dropper execution with C2 resolver |
| LuaJIT/Lua connecting to Polygon RPC | 95 | SmartLoader's exact C2 mechanism; LuaJIT has no legitimate reason to query Polygon |
| PowerShell/wscript connecting to Polygon RPC | 90 | LOLBin-based C2; no legitimate use case |
| certutil/bitsadmin/curl connecting to Polygon RPC | 80 | Download tool chain; correlate with process ancestry |
| node/npm connecting to Polygon RPC | 75 | Higher FP rate; could be legitimate Web3 developer tools — scope with asset groups |
| python/pip connecting to Polygon RPC | 70 | Could be Python DeFi tools; correlate with Lua execution ancestry |
| POST to bare IP from LOCALAPPDATA binary | 85 | StealC exfiltration pattern; no legitimate apps route data this way |
| DNS query to Polygon RPC domain (alone) | 70 | Enrichment-level IOC; insufficient alone |

## Associated Threat Actors

| Actor | Relationship |
|-------|-------------|
| SmartLoader Gang (FakeGit campaign) | Primary user of Polygon blockchain C2 for dead-drop C2 resolution; active February–April 2026 |
| StealC (MaaS, secondary payload) | Loaded by SmartLoader; exfiltrates via bare-IP POST after C2 address resolution |

## References

- [The Hacker News — SmartLoader Attack Uses Trojanized Oura MCP (2026-02)](https://thehackernews.com/2026/02/smartloader-attack-uses-trojanized-oura.html)
- [Hexastrike — 109 Fake GitHub Repos](https://hexastrike.com/resources/blog/threat-intelligence/cloned-loaded-and-stolen-how-109-fake-github-repositories-delivered-smartloader-and-stealc/)
- [SOC Prime — SmartLoader Analysis](https://socprime.com/active-threats/smartloader-analysis/)
- [Bitsight — StealC Infrastructure Disruption](https://www.bitsight.com/blog/bitsight-aids-disruption-efforts-on-amadey-malware-and-stealc-malware)
- [dRPC — polygon.drpc.org IOC Radar](https://socradar.io/free-tools/ioc-radar/polygon.drpc.org)
- [MITRE ATT&CK — T1102.002: Web Service: Bidirectional Communication](https://attack.mitre.org/techniques/T1102/002/)
- [MITRE ATT&CK — T1568: Dynamic Resolution](https://attack.mitre.org/techniques/T1568/)
- [MITRE ATT&CK — T1008: Fallback Channels](https://attack.mitre.org/techniques/T1008/)
- [EtherHiding comparison — GuardioLabs (2023)](https://labs.guard.io/etherhiding-hiding-web2-malicious-code-in-web3-smart-contracts-65ea78efad16)
