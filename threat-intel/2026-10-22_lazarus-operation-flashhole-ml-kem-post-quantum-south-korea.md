# Lazarus Group — Operation FlashHole: ML-KEM-1024 Post-Quantum C2 Encryption Targeting South Korean Organizations

**Date:** 2026-10-21–22
**Source:** Kaspersky Securelist — "Dissecting Operation FlashHole, a complex attack by Lazarus"
**Severity:** High
**Status:** Active campaign; IOC appendix available on Securelist

---

## Summary

Kaspersky's Global Research and Analysis Team (GReAT) disclosed Operation FlashHole, a sophisticated Lazarus Group campaign active since at least July 2025 targeting South Korean organizations in the software, construction, and wired communications manufacturing sectors. The campaign is notable for two innovations: exploitation of CrossWeb EX (a mandatory South Korean financial security product) as a watering-hole vector, and the deployment of LPEClient malware using NIST-standardized ML-KEM-1024 (Module-Lattice-based Key Encapsulation Mechanism) post-quantum encryption to protect C2 communications against decryption even by quantum-capable future adversaries.

Kaspersky assesses with medium-to-high confidence that Operation FlashHole is the work of the same actor responsible for Operation SyncHole, and is part of the DreamJob campaign cluster.

---

## Technical Details

### Initial Access

- **Spear-phishing** with customized GitHub Pages lures (themes: resume review, interior design portfolio)
- **Watering hole** via CrossWeb EX, a mandatory financial security software product used by South Korean organizations
- **AI-generated** fake profile photos and target-tailored lure websites

### Malware Chain

```
[CrossWeb EX / GitHub Pages lure]
        ↓
    TechHub (installer / dropper)
        ↓
    TouchHub (loader) + TouchShift (payload decryption stub)
        ↓
    ClientHub (network proxy / message buffer)
        ↓
    LPEClient (profiler / payload delivery) ← ML-KEM-1024 used here
        ↓
    Cubridge (modular backdoor, reflectively loaded)
```

### LPEClient ML-KEM-1024 Implementation

LPEClient receives four 1568-byte ML-KEM-1024 public key blocks from the C2 server. It uses these to establish a shared secret, then:

1. Encrypts communications via **GOST** symmetric cipher using the derived shared key
2. Routes encrypted messages through the **ClientHub** network buffer using message identifier `0xEF8C0D51`
3. Decrypts the final Cubridge payload using **Threefish** (after ML-KEM key exchange)

The use of NIST-standardized post-quantum key encapsulation (FIPS 203 / ML-KEM) represents a significant upgrade from conventional asymmetric key exchange and is the first observed use of a post-quantum standard by Lazarus in a production malware framework.

### Cubridge Backdoor

Cubridge is a modular, reflectively-loaded Windows backdoor. Capabilities include:
- Plugin/module loading
- File operations (read/write/delete)
- Process execution and management
- Network tunneling
- Screen capture and keylogging (depending on loaded plugins)

**Cross-vendor naming:**
| Vendor | TechHub | Cubridge |
|--------|---------|---------|
| Mandiant (GTIG) | CLOUDBURST | SIDESHOW |
| ESET | NickelLoader | LightlessCan |

---

## IOCs

### File Hashes (Partial — Full List at Securelist)

| Hash | Type | File | Context |
|------|------|------|---------|
| `2f8475a90a25624ed02f1d18d4e6d65d` | MD5 | `mscoree.dll` | TouchShift payload |
| `676fabe30a28b53925fba98e34b35986` | MD5 | `mscoree.dll` | TouchShift payload (alternate variant) |

*The complete IOC appendix including all hashes, domains, and IPs is published at:*
*https://securelist.com/lazarus-operation-flashhole/121541/*

---

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Phishing: Spearphishing Link |
| Technique ID | T1566.002 |
| Technique | Drive-by Compromise |
| Technique ID | T1189 |
| Secondary Tactic | Execution (TA0002) |
| Secondary Technique | User Execution: Malicious File (T1204.002) |
| Tertiary Tactic | Defense Evasion (TA0005) |
| Tertiary Technique | Obfuscated Files or Information (T1027) |
| Tertiary Technique | Reflective Code Loading (T1620) |
| Quaternary Tactic | Command and Control (TA0011) |
| Quaternary Technique | Encrypted Channel: Asymmetric Cryptography (T1573.002) — ML-KEM-1024 |
| Quaternary Technique | Proxy: Internal Proxy (T1090.001) — ClientHub message buffer |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Delivery |
| Exploitation |
| Installation |
| Command & Control (C2) |

---

## Threat Actor

| Field | Value |
|-------|-------|
| Name | Lazarus Group |
| Also Known As | HIDDEN COBRA, APT38 (overlapping), BlueNoroff (financial sub-cluster) |
| Attribution | DPRK (North Korea) state-sponsored |
| MITRE ID | G0032 |
| Related Operations | DreamJob, SyncHole, Operation FlashHole |
| Targets | South Korean software, construction, wired communications manufacturing organizations |

---

## Recommended Detections

1. **CrossWeb EX spawning unexpected processes** — particularly network-connected child processes or script interpreters
2. **ML-KEM-1024 public key blocks (1568-byte)** on network — unusual large binary blobs to non-standard ports
3. **Reflective DLL loading** from memory (no disk artifact) — Cubridge is loaded without touching disk
4. **GOST cipher usage** in otherwise standard Windows process traffic
5. **GitHub Pages domains** used as C2 staging (rare for legitimate applications)

---

## References

- [Kaspersky Securelist — Dissecting Operation FlashHole](https://securelist.com/lazarus-operation-flashhole/121541/)
- [Security Online — Lazarus Operation FlashHole](https://securityonline.info/lazarus-operation-flashhole/)
- [NetManageIT — Operation FlashHole: Lazarus Malware Chain Explained](https://blog.netmanageit.com/operation-flashhole-lazarus-south-korean-security-software/)
- [MITRE ATT&CK — Lazarus Group (G0032)](https://attack.mitre.org/groups/G0032/)
- [NIST FIPS 203 — ML-KEM (Module-Lattice Key Encapsulation)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)
