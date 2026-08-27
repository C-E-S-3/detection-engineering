---
scraped_at: "2026-08-27T00:00:00Z"
source_url: "https://www.sekoia.com/blog/unveiling-errtraffic-inside-a-growing-clickfix-malware-distribution-framework"
report_type: threat-intel
severity: high
title: "ErrTraffic v3 MaaS: LenAI Operator Uses Polygon Blockchain Dead-Drop to Deliver Cruciferra EDR-Killer via ClickFix (Late July–Aug 2026)"
---

# ErrTraffic v3 MaaS: LenAI Operator Uses Polygon Blockchain Dead-Drop to Deliver Cruciferra EDR-Killer via ClickFix

**Sources:** Sekoia (unveiling ErrTraffic), LevelBlue/SpiderLabs (Err-Hiding and Seek), eSentire (ErrTraffic and Cruciferra), Trinity Cyber, Infosecurity Magazine, GBHackers (all approximately late August 2026)  
**Severity:** High  
**Malware Families:** ErrTraffic v3 (ClickFix MaaS framework), Cruciferra (EDR-killing loader)  
**Threat Actor:** LenAI (operator/author)

---

## 1. IOCs

### Infrastructure Characteristics (No Specific Indicators Confirmed)

No specific C2 domain names, file hashes, or Polygon smart contract addresses have been confirmed from publicly accessible sources as of this report. The following infrastructure characteristics were reported by multiple vendors:

| Characteristic | Detail |
|----------------|--------|
| C2 hosting provider | Omegatech LTD (AS202412) — bulletproof hosting cluster |
| Domain count | Approximately 66 C2 domains |
| Common TLDs | `.click`, `.beer`, `.sbs`, `.shop` |
| Blocklist status | Domains included in Spamhaus SBL (Spamhaus Block List) |
| C2 resolution | Active C2 address stored in Polygon (MATIC) smart contract; resolved via EtherHiding `eth_call` query to `polygon.drpc.org` or `polygon-rpc.com` |
| Initial vector | Obfuscated JavaScript injection on compromised WordPress sites |
| ClickFix lure types | Fake Google reCAPTCHA, fake Cloudflare Turnstile, fake Windows BSOD |

Defenders should query for outbound `eth_call` requests to Polygon JSON-RPC endpoints from non-browser, non-developer processes (see existing detection: `detections/command_and_control/smartloader_polygon_blockchain_c2.md`).

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique | Usage |
|--------|-------------|-----------|-------|
| Initial Access | T1189 | Drive-by Compromise | ErrTraffic JavaScript injection on thousands of compromised WordPress sites redirects visitors to ClickFix lure pages |
| Initial Access | T1566 | Phishing | ClickFix lure presents fake CAPTCHA verification or BSOD "fix" requiring clipboard paste of a PowerShell command |
| Execution | T1059.001 | PowerShell | ClickFix lure copies a malicious PowerShell command to the victim's clipboard and instructs them to paste it in Run/Terminal; PowerShell retrieves and executes Cruciferra |
| Execution | T1204.002 | User Execution: Malicious File | Victim manually pastes and executes the PowerShell command, bypassing traditional download controls |
| Command and Control | T1568 | Dynamic Resolution | ErrTraffic v3 uses the EtherHiding technique: embedded JavaScript queries a Polygon smart contract to resolve the current C2 domain before fetching ClickFix lure JavaScript |
| Command and Control | T1102.002 | Web Service: Bidirectional Communication | Polygon blockchain serves as resilient dead-drop resolver; C2 domain rotation requires only a contract state update, making domain blocklisting ineffective |
| Defense Evasion | T1562.001 | Impair Defenses: Disable or Modify Tools | Cruciferra loader actively kills EDR processes and security tooling before delivering the final payload |
| Defense Evasion | T1027 | Obfuscated Files or Information | ErrTraffic JavaScript injection is obfuscated; Cruciferra employs packing/obfuscation to evade static detection |
| Defense Evasion | T1036 | Masquerading | ClickFix lures impersonate legitimate services (Google, Cloudflare, Windows) to establish victim trust |

---

## 3. Malware & Tools

### ErrTraffic v3

| Attribute | Detail |
|-----------|--------|
| Type | Subscription-based ClickFix Malware-as-a-Service (MaaS) framework |
| Operator | LenAI (threat actor alias) |
| First seen | Late 2025 (early versions); v3 with blockchain C2 from February 2026 |
| Pricing (as of Aug 2026) | $380/month subscription; source code $4,500 with lifetime updates |
| Distribution | ~66 C2 domains in Omegatech LTD AS202412; domains in Spamhaus SBL |
| Key innovation | v3 adopts EtherHiding via Polygon blockchain for C2 resolution — same technique as SmartLoader and WeedHack, now applied to ClickFix delivery |
| Lure variants | Google reCAPTCHA fake verification, Cloudflare Turnstile fake verification, Windows BSOD "fix" |
| Role in chain | Delivers JavaScript ClickFix lure to victims redirected from compromised WordPress sites; resolves active C2 via Polygon before each campaign wave |

### Cruciferra

| Attribute | Detail |
|-----------|--------|
| Type | EDR-killing loader / dropper |
| First seen | Active since at least 2025; associated with ErrTraffic since late July 2026 |
| Key capability | Kills EDR processes before delivering final payload (infostealer, RAT, or ransomware depending on affiliate) |
| Delivery | Second-stage payload retrieved via PowerShell clipboard-execution initiated by ErrTraffic ClickFix lure |

---

## 4. Threat Actor / Campaign Attribution

**Operator:** LenAI (cybercrime, financially motivated)

LenAI operates ErrTraffic as a subscription MaaS, selling campaign slots and builder access to downstream affiliates. The operator is distinct from the affiliates who choose which payload Cruciferra drops (infostealer, RAT, ransomware). LenAI is responsible for the WordPress compromise infrastructure, Polygon contract management, and the ClickFix lure builder.

**Campaign context:** Late July 2026 campaigns specifically delivered Cruciferra as the final payload, targeting Windows systems via the standard ClickFix clipboard injection pattern. The use of compromised WordPress sites as the initial redirect layer is consistent with established initial-access broker (IAB) patterns.

**Blockchain C2 ecosystem context:** ErrTraffic v3 joins a growing set of malware families using blockchain dead-drop resolvers (EtherHiding technique). Previously tracked examples in this repository:
- WeedHack (Ethereum, June 2026)
- EtherRAT (Ethereum, July 2026)
- SmartLoader / FakeGit (Polygon, June–July 2026)
- ViteVenom / PolinRider (TRON/Aptos, July 2026)
- Glassworm (Solana, May 2026)

---

## 5. Splunk Detection Searches

Note: Dedicated detections for EtherHiding (Ethereum), Polygon blockchain C2, and ClickFix user execution already exist in this repository. The searches below are reference searches; operators should activate the existing detections linked in section 6.

### Search 1: Polygon JSON-RPC Calls from Non-Browser Processes (ErrTraffic v3 C2 Resolution)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.dest_port IN (443, 80)
  AND (All_Traffic.dest="polygon.drpc.org" OR All_Traffic.dest="polygon-rpc.com"
       OR All_Traffic.dest="rpc-mainnet.maticvigil.com" OR All_Traffic.dest="matic-mainnet.chainstacklabs.com")
by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.process
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| where NOT match(process, "(?i)chrome|firefox|msedge|safari|opera|brave")
| eval risk_score=case(
    match(process, "(?i)powershell|cmd|wscript|cscript|mshta"), 90,
    match(process, "(?i)node|python|perl"), 75,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime src dest dest_port process risk_score
```

### Search 2: PowerShell Clipboard-Execution ClickFix Pattern (Cruciferra Stage 1)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name IN ("powershell.exe", "pwsh.exe")
  AND Processes.parent_process_name IN ("explorer.exe", "cmd.exe", "mshta.exe")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval clipboard_execution=if(
    NOT match(process, "(?i)-file|-f |-encodedcommand|-enc ") AND
    match(process, "(?i)iex|invoke-expression|downloadstring|webclient|bitstransfer|start-process"), 1, 0)
| where clipboard_execution=1
| eval risk_score=case(
    match(process, "(?i)iex.*downloadstring|invoke-expression.*downloadstring"), 90,
    match(process, "(?i)bitstransfer|Start-BitsTransfer"), 80,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score
```

---

## 6. Executive Summary

**ErrTraffic v3** is a subscription-based ClickFix Malware-as-a-Service (MaaS) operated by the threat actor **LenAI** since at least late 2025. The framework was substantially rebuilt in February 2026 to incorporate the **EtherHiding** technique, using Polygon (MATIC) smart contracts as a dead-drop resolver for C2 infrastructure — making domain-based blocking highly ineffective.

The campaign chain works as follows:
1. Compromised WordPress sites receive an obfuscated ErrTraffic JavaScript injection
2. The injection queries a Polygon smart contract to retrieve the current C2 address
3. The C2 delivers ClickFix JavaScript presenting a fake Google reCAPTCHA, Cloudflare Turnstile, or Windows BSOD page
4. The lure copies a malicious PowerShell command to the victim's clipboard and instructs them to execute it
5. The PowerShell command retrieves and executes **Cruciferra**, an EDR-killing loader
6. Cruciferra kills endpoint security tooling and delivers a final payload (infostealer, RAT, or ransomware per affiliate)

ErrTraffic v3's Polygon-based C2 joins an increasingly crowded ecosystem of blockchain dead-drop C2 techniques. In late July 2026, campaigns were observed delivering Cruciferra specifically, with ~66 C2 domains concentrated in bulletproof hosting provider Omegatech LTD (AS202412) and all listed in the Spamhaus SBL.

**Existing detections in this repository that cover ErrTraffic v3 activity:**
- `detections/command_and_control/smartloader_polygon_blockchain_c2.md` — Polygon JSON-RPC `eth_call` from non-browser processes
- `detections/command_and_control/etherhiding_ethereum_smart_contract_c2.md` — EtherHiding patterns
- `detections/execution/clickfix_user_execution_lure.md` — ClickFix clipboard execution
- `detections/initial_access/macos_clickfix_fake_captcha_launchagent.md` — macOS ClickFix variant

**Recommended additional defensive actions:**
1. Block or alert on outbound connections to Polygon JSON-RPC endpoints (`polygon.drpc.org`, `polygon-rpc.com`) from non-developer workstations
2. Add Omegatech LTD (AS202412) to threat intelligence feeds for proactive blocking
3. Implement Group Policy blocking of clipboard-initiated PowerShell execution (event ID 4104 script block logging)

---

## References

- [Sekoia — Unveiling ErrTraffic: Inside a Growing ClickFix Malware Distribution Framework](https://www.sekoia.com/blog/unveiling-errtraffic-inside-a-growing-clickfix-malware-distribution-framework)
- [LevelBlue SpiderLabs — Err-Hiding and Seek: How ErrTraffic v3 Leverages EtherHiding in ClickFix Campaign](https://www.levelblue.com/blogs/spiderlabs-blog/err-hiding-and-seek-how-errtraffic-v3-leverages-etherhiding-in-clickfix-campaign)
- [eSentire — Malware-as-a-Service Cocktail: ErrTraffic and Cruciferra - Killing Your EDR Since 2025](https://www.esentire.com/blog/malware-as-a-service-cocktail-errtraffic-and-cruciferra-killing-your-edr-since-2025)
- [Trinity Cyber — Behind the Curtain: How the ErrTraffic ClickFix Toolkit is Evolving](https://www.trinitycyber.com/blog/behind-the-curtain-clickfix-errtraffic-toolkit-is-evolving)
- [Infosecurity Magazine — MaaS Campaign Combines ClickFix, ErrTraffic and Cruciferra](https://www.infosecurity-magazine.com/news/maas-clickfix-errtraffic-cruciferra/)
- [MITRE ATT&CK — T1189: Drive-by Compromise](https://attack.mitre.org/techniques/T1189/)
- [MITRE ATT&CK — T1568: Dynamic Resolution](https://attack.mitre.org/techniques/T1568/)
- [MITRE ATT&CK — T1562.001: Impair Defenses](https://attack.mitre.org/techniques/T1562/001/)
- [threat-intel/2026-06-03_mcafee-weedhack-minecraft-maas-etherhiding.md](2026-06-03_mcafee-weedhack-minecraft-maas-etherhiding.md)
- [threat-intel/2026-07-07_bleepingcomputer-com-etherrat-teams-vishing-blockchain-c2.md](2026-07-07_bleepingcomputer-com-etherrat-teams-vishing-blockchain-c2.md)
