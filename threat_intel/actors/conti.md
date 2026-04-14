# Conti / Wizard Spider — Lineage & Tooling

This page traces the Conti ransomware operation from its Ryuk/TrickBot origins through its 2022 collapse into today's successor ecosystem. Conti is one of the most important case studies in ransomware lineage because its codebase, tooling, and personnel seeded a generation of follow-on groups — meaning a detection for classic Conti TTPs often covers half a dozen active operators.

> **Attribution convention in this repo:** "Wizard Spider" (CrowdStrike) and "TrickBot Group" refer to the same operators who ran TrickBot → Ryuk → Conti. Treat them as one evolving entity.

---

## Lineage at a Glance

```
                       Emotet (spam loader, partner op)
                             │
                             ▼
            TrickBot ───────►  BazarLoader / BazarBackdoor
            (banking trojan,           (Conti-era loader)
             loader)                           │
                │                              │
                ▼                              ▼
              Ryuk  ──────────────────────►  Conti
              (2018–2020)                    (2020–2022)
                                                │
                  ┌──────────────┬──────────────┼──────────────┬──────────────┐
                  ▼              ▼              ▼              ▼              ▼
               Royal          Black Basta    Quantum         Karakurt         Zeon / Diavol
             (→BlackSuit)                    (rapid enc)   (extortion-only)  (codebase reuse)
```

**Key dates:**

| Date | Event |
|------|-------|
| 2016 | Emotet emerges as a banking trojan; pivots to loader-as-a-service |
| 2016 | TrickBot first observed (Dyre successor) |
| 2018 | Ryuk ransomware first observed; deployed via TrickBot/Emotet chain |
| 2020 | Conti replaces Ryuk as Wizard Spider's flagship ransomware |
| Apr 2021 | BazarLoader adopted as primary Conti loader (replacing TrickBot on high-value targets) |
| Jan 2021 | Europol/international operation disrupts Emotet infrastructure (partial, rebuilt later) |
| May 2022 | Conti pledges support for Russia's invasion of Ukraine; Ukrainian insider leaks "ContiLeaks" |
| May–Jun 2022 | Conti formally shuts down, splinters into successor brands |
| 2022–present | Royal, Black Basta, Quantum, Karakurt, Zeon operate with Conti TTPs |
| 2023 | Royal rebrands to BlackSuit after law enforcement pressure |

---

## Predecessor: Ryuk (2018–2020)

Ryuk was the precursor ransomware run by the same Wizard Spider operators who later launched Conti. Understanding Ryuk matters because Conti is a direct evolution — not a separate operation.

| Attribute | Details |
|-----------|---------|
| **MITRE Software** | [S0446 - Ryuk](https://attack.mitre.org/software/S0446/) |
| **Operators** | Wizard Spider / TrickBot Group |
| **Delivery Chain** | Emotet → TrickBot → Ryuk ("Triple Threat") |
| **Primary Targets** | Healthcare, local government, large enterprises |
| **Notable Incidents** | Universal Health Services (Sep 2020), multiple US hospital attacks during COVID-19 |
| **End of Life** | Superseded by Conti in 2020; codebase inherited |

**Why the Ryuk → Conti transition matters for detections:**

- The loader infrastructure (TrickBot, Emotet, BazarLoader) is **unchanged** across both eras. Detections for TrickBot/Emotet C2 patterns cover both Ryuk-era and Conti-era initial access.
- Lateral movement patterns (Cobalt Strike beacons, PsExec, WMI) are identical.
- The encryption binaries differ, but the **operator tradecraft is continuous**. Analysts should treat "Ryuk TTPs" and "Conti TTPs" as a single body of tradecraft.

---

## Conti Core Tooling (2020–2022)

Reproduced from `THREAT_ACTORS.md` with additional context on evolution and replacement:

| Tool | Role | Notes on Evolution |
|------|------|--------------------|
| **Emotet** | Spam-driven loader (partner op) | Primary initial access 2018–2021; infrastructure disrupted Jan 2021 but rebuilt |
| **TrickBot** | Banking trojan / loader | Primary Ryuk/early-Conti loader; downgraded to commodity use as BazarLoader took over high-value ops |
| **BazarLoader / BazarBackdoor** | Stealthy loader for HVT | Purpose-built for Conti; lower detection surface than TrickBot |
| **Anchor / Anchor_DNS** | Backdoor for high-value targets | DNS-tunneled C2 for long-dwell access |
| **Cobalt Strike** | C2 / post-exploitation | Universal across all operators — the single most important Conti detection target |
| **Conti Ransomware** | Encryption payload | Multi-threaded, targets SMB shares; source code leaked Feb–Mar 2022 (ContiLeaks) |
| **Ryuk** | Predecessor encryption payload | Replaced by Conti in 2020 but tradecraft continuous |
| **Meterpreter** | Post-exploitation | Less common than Cobalt Strike but observed |
| **AdFind** | Active Directory recon | Conti playbook staple — detection of `adfind.exe` with AD query flags is high-fidelity |
| **Rclone** | Exfiltration | Staged data then pushed to MEGA or attacker-controlled cloud |
| **MEGA / MEGASync** | Cloud exfiltration | Preferred exfil destination |
| **Router Scan / NLBrute** | Initial access | RDP brute force for edge access |

### Cobalt Strike as the Universal Pivot

Every successor group listed below uses Cobalt Strike. If you can only invest in one Conti-lineage detection, make it Cobalt Strike beacon detection (named pipe patterns, default malleable C2 profiles, sleep jitter anomalies, spawnto behavior).

---

## Successors & Splinter Groups (2022–present)

After the May 2022 ContiLeaks disclosure and the operation's formal shutdown, the Conti operators dispersed into several branded groups. All inherit the core playbook — loader → Cobalt Strike → AD recon → SMB lateral → exfil via Rclone/MEGA → encryption.

### Royal / BlackSuit (Active)

| Attribute | Details |
|-----------|---------|
| **Origin** | Core Conti operators; branded "Royal" in Sep 2022 |
| **Rebrand** | Became "BlackSuit" in mid-2023 after law enforcement attention |
| **Targets** | Healthcare, education, manufacturing; heavy US focus |
| **Key Tools** | Cobalt Strike, Chisel (tunneling), RClone, PsExec, AdFind |
| **Notable Trait** | Callback phishing (fake subscription renewals → TOAD → ScreenConnect abuse) |

### Black Basta (Active)

| Attribute | Details |
|-----------|---------|
| **Origin** | Former Conti operators; surfaced Apr 2022 |
| **Delivery** | QakBot (Qbot) loader → Cobalt Strike → Brute Ratel C4 |
| **Targets** | Manufacturing, construction, critical infrastructure |
| **Key Tools** | QakBot, Cobalt Strike, Brute Ratel C4, SystemBC, Mimikatz, PsExec |
| **Notable Trait** | Heavy use of Brute Ratel as Cobalt Strike alternative; BYOVD EDR termination |

### Quantum (Inactive)

| Attribute | Details |
|-----------|---------|
| **Origin** | Conti subgroup spun out early 2022 |
| **Specialty** | "Quick ransomware" — compressed intrusion-to-encryption timelines (hours, not days) |
| **Delivery** | IcedID → Cobalt Strike → Quantum locker |
| **Status** | Absorbed into other Conti successors; activity tapered 2023 |

### Karakurt (Disrupted)

| Attribute | Details |
|-----------|---------|
| **Origin** | Conti data-extortion arm (no encryption) |
| **Tactic** | Pure exfiltration + shakedown; threatens publication on leak site |
| **Key Tools** | Cobalt Strike, Mimikatz, AnyDesk, Rclone, 7-Zip for archiving |
| **Status** | US Treasury sanctioned 2022; reduced activity |

### Zeon / Diavol (Low activity / Inactive)

- **Zeon** — splinter using leaked Conti encryptor source
- **Diavol** — TrickBot-operator-linked ransomware; likely a Conti testbed that never achieved primary-brand status

---

## Detection Implications

Because these groups share >80% of their post-initial-access tradecraft, a single detection often covers the entire lineage. When authoring or reviewing detections, use the following tagging guidance:

| Observed Technique | Tag With |
|--------------------|----------|
| TrickBot injector / module execution | Conti, Ryuk, Wizard Spider |
| Emotet loader macro / download cradle | Conti, Ryuk (via partner op), generic commodity |
| BazarLoader HTTP C2 pattern | Conti (specifically) |
| QakBot loader | Black Basta (primary), Conti successors generally |
| IcedID loader | Quantum (primary), Conti successors |
| AdFind with AD enumeration flags | Conti, Royal/BlackSuit, Black Basta |
| Cobalt Strike named pipes | All Conti-lineage groups (plus unrelated actors — not uniquely attributive) |
| Brute Ratel C4 | Black Basta (primary), ALPHV/BlackCat |
| Rclone to MEGA endpoints | Conti, Royal/BlackSuit, Karakurt |
| Callback phishing → ScreenConnect / AnyDesk | Royal/BlackSuit (signature TTP) |

### Where to Invest Detection Effort

Ordered by coverage-per-rule for this lineage:

1. **Cobalt Strike beacon behavior** — covers every successor
2. **AdFind reconnaissance** — near-universal in the playbook, rarely used legitimately
3. **Rclone with cloud storage destinations** — covers exfil across all successors
4. **SMB lateral movement via PsExec / Impacket** — core of the playbook
5. **BazarLoader / QakBot / IcedID loader patterns** — covers the initial access layer across successors
6. **Callback phishing → RMM abuse (ScreenConnect, AnyDesk, TeamViewer)** — specifically Royal/BlackSuit but rising across the ecosystem

---

## References

- [MITRE ATT&CK G0102 — Wizard Spider](https://attack.mitre.org/groups/G0102/)
- [MITRE ATT&CK S0446 — Ryuk](https://attack.mitre.org/software/S0446/)
- [MITRE ATT&CK S0575 — Conti](https://attack.mitre.org/software/S0575/)
- [CISA AA21-265A — Conti Ransomware](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-265a)
- [CISA AA23-061A — Royal Ransomware](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-061a)
- [CISA AA24-131A — Black Basta](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-131a)
- ContiLeaks (Feb–Mar 2022) — internal chat logs and source code leak following Conti's pro-Russia statement
- [Mandiant — FIN12 / Wizard Spider reporting](https://www.mandiant.com/resources/blog)
