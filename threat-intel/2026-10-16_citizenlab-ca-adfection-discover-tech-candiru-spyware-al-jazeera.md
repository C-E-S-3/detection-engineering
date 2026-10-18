# AdFection: Candiru Zero-Click Spyware Delivered via Discover-Tech Targeted Advertising

**Source:** https://citizenlab.ca/research/how-discover-tech-turned-targeted-ads-into-a-pipeline-for-spyware/  
**Published:** 2026-10-15  
**Reported by:** Citizen Lab (University of Toronto)  
**Date Added:** 2026-10-18  
**Secondary Coverage:** https://cybersecuritynews.com/discover-tech-ad-network-used-to-deploy-candiru-spyware/

---

## Summary

Citizen Lab published research documenting how Discover-Tech Ltd., an online advertising network, functioned as a delivery pipeline for Candiru mercenary spyware against at least 45 Al Jazeera-affiliated devices between 2024 and 2025. Researchers analyzed approximately 4 billion real-time bidding (RTB) records from March–June 2026 to reconstruct the delivery mechanism.

The technique — dubbed **AdFection** — exploits the trusted ad ecosystem to deliver zero-click browser exploits to individually targeted devices. No user interaction beyond loading a web page with an ad slot is required.

---

## Threat Actors

### Candiru
- Israeli mercenary spyware vendor; sells Windows and browser exploits to government clients
- Previously identified in Citizen Lab and Microsoft research (2021); this represents renewed activity
- Linked in this report to Bindecy Ltd. and Intelos Ltd. as affiliated entities
- Delivers "DevilsTongue" Windows spyware (MITRE S0693)

### Discover-Tech Ltd.
- Ad network operator functioning as the delivery infrastructure
- Provided ad-serving code that performs device fingerprinting, target selection, and redirect to Candiru validator/exploit server
- Following Citizen Lab's disclosure, Google, IAB Europe, Beeswax, Vungle, and Eskimi suspended or paused Discover-Tech access

---

## Attack Chain (AdFection)

```
Target device loads a web page with an ad slot
  └─ RTB auction won by Discover-Tech
        └─ Discover-Tech ad code executes in browser
              └─ Device fingerprinting check
                    ├─ Non-target: normal ad rendered
                    └─ Target matched: silent redirect to Candiru validator
                          └─ Exploit server → zero-click browser exploit
                                └─ Candiru DevilsTongue C2 beacon
```

Key characteristics:
- **Zero-click**: no user action required beyond visiting a page with an ad slot
- **Precision targeting**: fingerprinting ensures the exploit fires only against selected individuals
- **Scale disguise**: millions of normal ad impressions mask rare exploit deliveries in RTB logs
- **Platform agnostic**: operates through any publisher that integrates Discover-Tech ad code

---

## Victims / Targeting

- 45+ confirmed Al Jazeera-associated devices (2024–2025 targeting period)
- Researchers found evidence suggesting use against journalists in other organizations
- Specific countries and journalist identities not disclosed by Citizen Lab

---

## IOCs

**Hash (unverified against primary source):**
| Indicator | Type | Confidence | Note |
|-----------|------|------------|------|
| `255869de85e2a171993fc5eb8a556d873a1b8966e040f6f55926f2fa2d595cc8` | SHA256 | Low — secondary source only | Reported as Windows DLL linked to Candiru C2 infrastructure by CybersecurityNews.com; **not confirmed against the primary Citizen Lab report**; treat as hypothesis only |

**Domain and IP IOCs:**  
No Discover-Tech or Candiru C2 domains/IPs were available in publicly-accessible search results. Full indicator appendix is in the Citizen Lab primary report.

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Description |
|--------|-----------|-------------|
| Initial Access (TA0001) | T1189 — Drive-by Compromise | Zero-click exploit delivered via targeted ad on any webpage |
| Initial Access (TA0001) | T1195.002 — Compromise Software Supply Chain | Ad network supply chain leveraged to inject exploit delivery |
| Execution (TA0002) | T1203 — Exploitation for Client Execution | Browser exploit fired without user interaction |
| Defense Evasion (TA0005) | T1027 — Obfuscated Files or Information | Fingerprint check hides exploit from non-targeted requests |
| Command and Control (TA0011) | T1071.001 — Application Layer Protocol: Web Protocols | Candiru DevilsTongue C2 communications |

**Kill Chain Phases:** Delivery, Exploitation

---

## Detection Notes

Detection of AdFection-style delivery is extremely difficult at the network or endpoint layer for defenders because:
1. The ad code runs in a legitimate browser session alongside thousands of other ad scripts
2. No file is dropped until after the exploit fires
3. The targeting check prevents sandbox/researcher systems from seeing the exploit path

**Defensive mitigations (non-detection):**
- Browser isolation / Remote Browser Isolation (RBI) for high-risk users (journalists, executives, activists)
- Ad-blocking at the DNS or proxy layer for sensitive populations
- Monitor for browsers spawning unexpected child processes (covered by existing ClickFix/browser exploit detections)

**Network hunting (limited value):** IOC-based blocking on Discover-Tech infrastructure if domains/IPs become available from the primary report.

---

## Broader Context

This report is part of a growing body of evidence that the real-time bidding advertising ecosystem can be weaponized as a precision exploit delivery mechanism. The 4 billion RTB record analysis performed by Citizen Lab is the largest-scale forensic reconstruction of an ad-based attack chain to date.

---

## References

- https://citizenlab.ca/research/how-discover-tech-turned-targeted-ads-into-a-pipeline-for-spyware/
- https://attack.mitre.org/techniques/T1189/
- https://attack.mitre.org/software/S0693/ (DevilsTongue)
- https://citizenlab.ca/2021/07/hooking-candiru-another-mercenary-spyware-vendor-comes-into-focus/ (prior Citizen Lab Candiru research)
- https://www.microsoft.com/en-us/security/blog/2021/07/15/protecting-customers-from-a-private-sector-offensive-actor-using-0-day-exploits-and-devilstongue-malware/ (Microsoft MSTIC prior research)
