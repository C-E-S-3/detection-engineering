# Threat Actors & Malware Gangs

This document maps the relationships between ransomware-as-a-service (RaaS) operations, their known affiliates, and associated tooling. Use this as a reference when tagging detections with threat actor metadata.

> **Why this matters:** When a new threat actor emerges, they rarely bring entirely new TTPs. By mapping actors to techniques, we can immediately identify which existing detections apply to a new group and where gaps remain.

---

## How to Use This Reference

1. **Tagging detections** — Every detection in this repo should list relevant threat actors in its `Associated Threat Actors` section. Use the actor names and aliases documented here for consistency.
2. **New actor onboarding** — When a new threat actor or affiliate is identified, add them to the appropriate section below and review existing detections that cover their known TTPs. Update the `Associated Threat Actors` field in each matching detection.
3. **Individual actor pages** — Detailed TTP breakdowns for each actor live in dedicated pages linked from the tables below. As coverage grows, create per-actor files under `threat_intel/actors/`.

```
threat_intel/
├── actors/
│   ├── conti.md              # (planned)
│   ├── darkside.md           # (planned)
│   ├── lockbit.md            # (planned)
│   ├── blackcat_alphv.md     # (planned)
│   ├── lazarus.md            # (planned)
│   └── ...
├── gootloader_ttp_analysis.md
```

---

## Ransomware-as-a-Service (RaaS) Operations

RaaS operations provide ransomware infrastructure to affiliates in exchange for a percentage of ransom payments. Understanding the RaaS ecosystem is critical because:

- **Affiliates move between RaaS platforms**, carrying their TTPs with them
- **Tooling is shared** across operations — a detection for one group often covers others
- **Rebrands are common** — a "new" group may be a continuation of a previous operation

### Conti (Wizard Spider / TrickBot Group)

| Attribute | Details |
|-----------|---------|
| **Also Known As** | Wizard Spider, Gold Blackburn, TrickBot Group |
| **Active** | 2020–2022 (formally disbanded; members dispersed to successor groups) |
| **MITRE Group** | [G0102 - Wizard Spider](https://attack.mitre.org/groups/G0102/) |
| **RaaS Model** | Salaried operators + affiliate model |
| **Primary Targets** | Healthcare, government, critical infrastructure |
| **Successor Groups** | Royal → BlackSuit, Black Basta, Quantum, Karakurt, Zeon |

**Associated Malware & Tools:**

| Tool | Type | Purpose |
|------|------|---------|
| Conti Ransomware | Ransomware | File encryption, data extortion |
| TrickBot | Loader / Banking Trojan | Initial access, credential theft, lateral movement |
| BazarLoader / BazarBackdoor | Loader | Initial access, C2 |
| Cobalt Strike | C2 Framework | Post-exploitation, lateral movement |
| Emotet | Loader (partner operation) | Spam-driven initial access, TrickBot delivery |
| Ryuk | Ransomware (predecessor) | File encryption — preceded Conti |
| Anchor | Backdoor | Stealthy long-term access for high-value targets |
| Meterpreter | Post-exploitation | Shellcode injection, lateral movement |
| AdFind | Reconnaissance | Active Directory enumeration |
| Rclone | Exfiltration | Data staging and cloud exfiltration |
| MEGA | Exfiltration | Cloud-based data exfiltration |

**Known Affiliates & Splinter Groups:**

| Affiliate / Splinter | Relationship | Status |
|-----------------------|-------------|--------|
| [Royal / BlackSuit](threat_intel/actors/conti.md) | Core Conti members formed Royal, later rebranded to BlackSuit | Active |
| [Black Basta](threat_intel/actors/conti.md) | Former Conti members launched Black Basta | Active |
| [Quantum](threat_intel/actors/conti.md) | Conti subgroup focused on rapid encryption | Inactive |
| [Karakurt](threat_intel/actors/conti.md) | Data extortion arm — no encryption, pure theft | Disrupted |
| [Zeon](threat_intel/actors/conti.md) | Splinter group using Conti codebase | Low activity |
| [Diavol](threat_intel/actors/conti.md) | Ransomware linked to TrickBot operators | Inactive |

---

### DarkSide / BlackMatter / ALPHV (BlackCat)

| Attribute | Details |
|-----------|---------|
| **Also Known As** | Carbon Spider (CrowdStrike), FIN7-adjacent |
| **Active** | DarkSide: 2020–2021, BlackMatter: 2021, ALPHV/BlackCat: 2021–2024 |
| **MITRE Group** | [G0119 - DarkSide](https://attack.mitre.org/groups/G0119/) |
| **RaaS Model** | Affiliate-based, 75/25 to 90/10 split |
| **Primary Targets** | Critical infrastructure, energy, legal, manufacturing |
| **Notable Incident** | Colonial Pipeline attack (May 2021) |
| **Evolution** | DarkSide → BlackMatter → ALPHV/BlackCat |

**Associated Malware & Tools:**

| Tool | Type | Purpose |
|------|------|---------|
| DarkSide Ransomware | Ransomware | Linux and Windows encryption |
| BlackMatter Ransomware | Ransomware | Rebrand of DarkSide |
| ALPHV / BlackCat | Ransomware | Rust-based, cross-platform encryption |
| Cobalt Strike | C2 Framework | Post-exploitation, lateral movement |
| Brute Ratel C4 | C2 Framework | EDR evasion, post-exploitation |
| SystemBC | Proxy / Backdoor | SOCKS5 proxy for C2 tunneling |
| Mimikatz | Credential Dumping | LSASS credential extraction |
| PsExec | Lateral Movement | Remote execution via SMB |
| Metasploit | Exploitation Framework | Initial access, post-exploitation |
| MEGASync / Rclone | Exfiltration | Data exfiltration to cloud storage |
| Fendr / ExMatter | Exfiltration | Automated data exfiltration tool |

**Known Affiliates:**

| Affiliate | Relationship | Notable Activity |
|-----------|-------------|-----------------|
| UNC2628 | ALPHV/BlackCat affiliate | Healthcare sector targeting |
| Scattered Spider (UNC3944) | ALPHV affiliate | Social engineering, SIM swapping, MGM/Caesars attacks |
| FIN7 overlap | Shared tooling & personnel | Initial access operations |
| Notchy | ALPHV affiliate | Change Healthcare attack, alleged $22M non-payment |

---

### LockBit (Gold Mystic)

| Attribute | Details |
|-----------|---------|
| **Also Known As** | Gold Mystic (Secureworks), Water Selkie (Trend Micro) |
| **Active** | 2019–present (disrupted by Operation Cronos, Feb 2024) |
| **MITRE Software** | [S1091 - LockBit](https://attack.mitre.org/software/S1091/) |
| **RaaS Model** | Affiliate-based, 80/20 split (affiliate keeps 80%) |
| **Primary Targets** | Opportunistic — all sectors and geographies |
| **Variants** | LockBit 1.0, LockBit 2.0 (Red), LockBit 3.0 (Black), LockBit Green |

**Associated Malware & Tools:**

| Tool | Type | Purpose |
|------|------|---------|
| LockBit Ransomware (1.0/2.0/3.0) | Ransomware | File encryption with self-spreading |
| StealBit | Exfiltration | Purpose-built automated data exfiltration |
| Cobalt Strike | C2 Framework | Post-exploitation, lateral movement |
| Metasploit | Exploitation Framework | Initial access, exploitation |
| Mimikatz | Credential Dumping | LSASS credential extraction |
| PsExec | Lateral Movement | Remote execution via SMB |
| ProxyShell / ProxyLogon exploits | Exploitation | Exchange server initial access |
| AnyDesk / TeamViewer | Remote Access | Legitimate RMM abuse for persistence |
| GMER / PCHunter / Process Hacker | Defense Evasion | Security tool termination (BYOVD) |
| Plink (PuTTY Link) | Tunneling | SSH tunneling for C2 |

**Known Affiliates:**

| Affiliate | Relationship | Notable Activity |
|-----------|-------------|-----------------|
| Affiliates (100+) | Various independent operators | LockBit had the largest affiliate network of any RaaS |
| Evil Corp (suspected overlap) | Affiliate / tool sharing | LockBit used to bypass OFAC sanctions on Evil Corp |
| National Health Service attacker | LockBit affiliate | UK NHS supply chain attack |
| Pendragon attacker | LockBit affiliate | $60M ransom demand against UK car dealership |

---

## Affiliate Crossover Map

Affiliates frequently move between RaaS platforms. This table tracks known crossover to help anticipate TTP reuse.

| Affiliate / Group | RaaS Platforms Used | Primary TTPs |
|-------------------|-------------------|--------------|
| Scattered Spider (UNC3944) | ALPHV/BlackCat, Qilin | Social engineering, MFA fatigue, identity provider abuse, cloud-native lateral movement |
| FIN7 | DarkSide, BlackMatter, ALPHV, REvil | Phishing, JavaScript backdoors, supply chain compromise |
| Evil Corp (Indrik Spider) | LockBit, WastedLocker, Hades, Phoenix | SocGholish fake updates, Dridex, BYOVD |
| Former Conti operators | Royal/BlackSuit, Black Basta, Quantum, Karakurt | BazarLoader, Cobalt Strike, ADFind reconnaissance |
| Emotet operators | Conti (partnership), various | High-volume phishing, loader delivery |
| UNC2628 | REvil, ALPHV/BlackCat | Exploitation of edge devices, Cobalt Strike |

---

## Shared Tooling Across Groups

These tools appear across multiple threat actor operations. Detections for these tools provide broad coverage regardless of which actor is using them.

| Tool | Used By | Detection Priority |
|------|---------|--------------------|
| **Cobalt Strike** | Conti, LockBit, DarkSide, ALPHV, virtually all RaaS | Critical — most common post-exploitation framework |
| **Mimikatz** | All RaaS operations | Critical — credential dumping is universal |
| **PsExec / Remote Services** | Conti, LockBit, ALPHV, Medusa | High — primary lateral movement method |
| **Rclone / MEGASync** | Conti, DarkSide, LockBit | High — most common exfiltration tools |
| **AdFind** | Conti, Black Basta | High — AD reconnaissance |
| **Brute Ratel C4** | ALPHV/BlackCat, Black Basta | High — emerging Cobalt Strike alternative |
| **AnyDesk / TeamViewer** | LockBit, Conti, various | Medium — legitimate tool abuse |
| **SystemBC** | DarkSide, Conti, Ryuk | Medium — proxy-based C2 tunneling |
| **GMER / Process Hacker** | LockBit, various (BYOVD) | High — security tool termination |
| **Impacket (wmiexec/smbexec)** | Conti, Medusa, various | High — lateral movement via SMB/WMI |

---

## Nation-State & Non-RaaS Threat Actors

These actors operate independently from the RaaS ecosystem but are tracked in this repo due to detection overlap.

| Actor | Type | MITRE Reference | Key TTPs | Repo Detections |
|-------|------|----------------|----------|-----------------|
| [Lazarus Group (HIDDEN COBRA)](https://attack.mitre.org/groups/G0032/) | Nation-State (DPRK) | [G0032](https://attack.mitre.org/groups/G0032/) | Spearphishing, DLL sideloading, LOLBAS, DGA C2, cryptocurrency theft | [11 detections](detections/) |
| [Gootloader (UNC2565)](https://attack.mitre.org/software/S1138/) | Malware Loader / Access Broker | [S1138](https://attack.mitre.org/software/S1138/) | SEO poisoning, JS execution, registry stuffing, fileless PowerShell | [13 detections](detections/) |
| [GodLoader](threat_intel/) | Malware Loader | — | Godot engine abuse, defender exclusion, web service C2 | [2 detections](detections/) |
| [Medusa Ransomware](https://attack.mitre.org/software/S1131/) | Ransomware Operator | [S1131](https://attack.mitre.org/software/S1131/) | SMBExec/WMIExec lateral movement, credential dumping | [2 detections](detections/) |
| Qilin Ransomware Group (GOLD HARVEST / Agenda) | Ransomware Operator (RaaS) | [S1242](https://attack.mitre.org/software/S1242/) | Stolen credential initial access (Telegram/Breach Forums), EDR killer BYOVD (300+ drivers), geo-fencing against post-Soviet locale settings, 6-day avg dwell time; 500+ victims in 2026; exploited CVE-2026-50751 (Check Point VPN IKEv1 auth bypass) for initial access; uses DonPAPI, NetExec, XenoRAT, MeshCentral; Chrome credential theft; safe-mode reboot EDR bypass; Linux/ESXi variant with openssl enc for file encryption; targets manufacturing, healthcare, critical infrastructure | [8 detections](wazuh/rules/cve-2026-06-24-n8n-checkpoint-qilin-winkernel.xml) |
| UAT-10608 | Threat Cluster | — | CVE-2025-55182 (React2Shell) exploitation, NEXUS Listener C2, automated credential harvesting | [1 detection](detections/) |
| EvilTokens / Storm-237 | PhaaS / Cybercrime | — | OAuth device code phishing, Microsoft 365 token theft, QR code phishing lures | [1 detection](detections/) |
| CrystalRAT (CrystalX RAT) | MaaS RAT | — | WebSocket C2, keylogging, clipboard hijacking (crypto theft), ChaCha20 encryption | [1 detection](detections/) |
| UNC5221 | Nation-State APT (China-nexus) | — | CVE-2025-22457 Ivanti VPN exploitation, SPAWN ecosystem (TRAILBLAZE, BRUSHFIRE, SPAWNSNARE, SPAWNWAVE, SPAWNSLOTH) | [1 detection](detections/) |
| TeamPCP | Supply Chain Threat Actor | — | GitHub Actions and PyPI/npm package backdooring; CI/CD credential theft; ICP blockchain C2 | [1 detection](detections/) |
| UNC5454 / Earth Lamia (UNC6586, UNC6588, UNC6595, UNC6600, UNC6603) | Nation-State APT (China-nexus) | — | CVE-2025-55182 exploitation deploying SNOWLIGHT, MINOCAT, COMPOOD, HISONIC, ANGRYREBEL.LINUX, XMRIG | [1 detection](detections/) |
| Amaranth Dragon | Nation-State APT (China-nexus) | — | CVE-2026-3502 TrueConf exploitation, Havoc C2, UAC bypass via iscicpl.exe, targets SE Asian government/military | [1 detection](detections/) |
| Handala (Hatef / Hamsa / Handala Hack Team) | Iranian MOIS-linked Hacktivist | — | Compromises Windows domain admin, creates Azure AD Global Administrator for persistence, deploys data-wiping malware at scale; 2026 Stryker attack wiped ~80,000 devices; targets Israeli organizations and affiliated companies; linked to Iran Ministry of Intelligence and Security | [1 detection](detections/) |
| UNC1069 (North Korea) | Nation-State APT (DPRK) | — | Supply chain attack on Axios npm ecosystem delivering WAVESHAPER.V2 cross-platform Python RAT (Linux/macOS/Windows); uses trojanized npm packages (plain-crypto-js) and obfuscated JavaScript dropper (setup.js); C2 via sfrclak.com and 142.11.206.73 | [IOCs tracked](iocs/) |

---

## Tagging Detections with Threat Actor Info

When adding or updating a detection, use this format in the `Associated Threat Actors` section:

```markdown
## Associated Threat Actors

| Actor | Relationship to Detection |
|-------|--------------------------|
| LockBit | Uses BYOVD technique for security tool termination |
| Conti | Operators observed using similar driver-based EDR evasion |
| ALPHV/BlackCat | Affiliates reported using vulnerable driver loading |
```

### Tagging Guidelines

1. **Be specific** — Explain *how* the actor uses the detected technique, not just that they exist
2. **Include aliases** — List primary name and common aliases (e.g., "Lazarus Group (HIDDEN COBRA, Diamond Sleet)")
3. **Note confidence level** — Distinguish between confirmed usage and suspected/reported usage
4. **Cross-reference RaaS vs affiliate** — If a technique is used by an affiliate rather than the RaaS platform itself, note which affiliate

### When a New Threat Actor Emerges

Follow this workflow:

1. **Document the actor** — Add an entry to the appropriate section in this file
2. **Map known TTPs** — List their MITRE ATT&CK techniques
3. **Search existing detections** — Review detections covering those techniques
4. **Update detection metadata** — Add the new actor to the `Associated Threat Actors` section of each matching detection
5. **Identify gaps** — Note any TTPs not covered by existing detections and create new detection files as needed
6. **Create a detailed actor page** — If warranted, create a dedicated file under `threat_intel/actors/`

---

## References

- [MITRE ATT&CK Groups](https://attack.mitre.org/groups/)
- [MITRE ATT&CK Software](https://attack.mitre.org/software/)
- [CISA Cybersecurity Advisories](https://www.cisa.gov/news-events/cybersecurity-advisories)
- [Mandiant Threat Intelligence](https://www.mandiant.com/resources/blog)
- [CrowdStrike Adversary Universe](https://www.crowdstrike.com/adversaries/)
- [Microsoft Threat Intelligence](https://www.microsoft.com/en-us/security/blog/topic/threat-intelligence/)
- [Secureworks Threat Profiles](https://www.secureworks.com/research/threat-profiles)
- [CISA #StopRansomware Advisories](https://www.cisa.gov/stopransomware)
