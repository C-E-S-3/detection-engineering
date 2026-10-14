---
scraped_at: "2026-10-14T00:00:00Z"
source_url: "https://www.crowdstrike.com/en-us/blog/fbi-disrupts-famous-chollima-operation-with-crowdstrike-assistance/"
report_type: threat-intel
severity: high
title: "CrowdStrike October 13 2026: FBI + CrowdStrike Disrupt FAMOUS CHOLLIMA (DPRK IT Worker) Laptop Farm Operation — 187 KVM Devices Seized, 2 Arrests, 70+ US Employers Affected"
---

## 1. IOCs

### Domains

No domains published in secondary reporting (laptop farm disrupted; C2 infrastructure not disclosed).

### IPs

No IPs published in secondary reporting.

### Hashes

No hashes published in secondary reporting.

### Behavioral / Device Indicators

| Indicator | Context |
|-----------|---------|
| Video capture cards presenting as webcam devices (Device ID masquerade) | FAMOUS CHOLLIMA disguises hardware video capture cards (used for remote KVM access) as webcams in device profiles to evade HR/IT verification checks since May 2026 |
| Reused MAC addresses and serial numbers across victim organizations | Same MAC/serial values observed on devices enrolled at multiple US employers; cross-organization correlation IOC |
| Device hardware hash spoofing | FAMOUS CHOLLIMA spoofs hardware fingerprints to pass device compliance checks and evade identity verification controls |

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Initial Access | T1078.002 | Valid Accounts: Domain Accounts | DPRK IT workers obtain fraudulent employment using stolen/fabricated identities; access is fully legitimate from the employer's perspective |
| Defense Evasion | T1036 | Masquerading | Hardware video capture cards disguised as webcam devices in device profiles; fake identities and resumes used to pass HR screening |
| Defense Evasion | T1562 | Impair Defenses | Device hardware hash spoofing to bypass corporate device compliance and identity verification controls |
| Defense Evasion | T1036.005 | Masquerading: Match Legitimate Name or Location | Reuse of MAC addresses and serial numbers across victim organizations to appear as legitimate enrolled devices |
| Impact | T1657 | Financial Theft | Approximately $3 million USD generated from fraudulent salaries across 70+ US employer victims |

---

## 3. Incident Summary

### FAMOUS CHOLLIMA Operation Lonestar Roundup (FBI Disruption October 13, 2026)

- **Threat Actor:** FAMOUS CHOLLIMA (CrowdStrike tracking name; North Korea / DPRK regime-directed IT worker scheme; active since at least 2021)
- **Operation Name:** Operation Lonestar Roundup (FBI/DOJ operation name)
- **Disruption Actions:**
  - 187 hardware KVM (Keyboard-Video-Mouse) devices seized during law enforcement operations in Texas
  - 2 individuals arrested in Ohio in connection with the scheme
  - Operation conducted with CrowdStrike intelligence assistance
- **Scope of Compromise:**
  - 70+ US employers affected across critical sectors
  - Approximately $3 million USD generated through fraudulent employment
  - Critical US industry sectors targeted (specific sectors not publicly disclosed)
- **New Tradecraft (observed from May 2026 onward):**
  - **Video capture card masquerade:** FAMOUS CHOLLIMA operatives configure hardware video capture cards to present as standard webcam devices in Windows device profiles. This bypasses HR video interview requirements and ongoing identity verification controls that rely on webcam presence/activity as a liveness signal.
  - **Device hash spoofing:** Hardware fingerprints on managed devices are spoofed to pass MDM device compliance policies and corporate identity verification requirements.
  - **MAC/serial reuse across victims:** The same MAC addresses and device serial numbers are reused across multiple employer enrollments, providing a cross-organization hunting opportunity.
- **Operational Model:**
  - DPRK operatives apply for remote IT jobs using stolen or fabricated identities and credentials
  - Employers ship laptops to domestic "laptop farm" facilitators (mules) who configure KVM hardware to remotely relay device access to DPRK operators
  - Operators appear to work normally from legitimate employer devices while actually operating from overseas
  - Fraudulent salaries are funneled back to DPRK regime
- **Detection Guidance:**
  - Audit device enrollment for duplicate MAC addresses or serial numbers across the organization or correlated across industry peers
  - Investigate devices where webcam device IDs correspond to video capture card hardware families (e.g., AVerMedia, Elgato, Magewell product IDs)
  - Review remote employment onboarding for inconsistencies: video interview liveness artifacts, location discrepancies between stated location and VPN/IP geolocation
  - FAMOUS CHOLLIMA tradecraft was catalogued in joint FBI/CISA advisory IC3 Alert I-100123-PSA (original 2023 IT worker scheme warning); updated guidance expected following this disruption

---

## 4. References

- [CrowdStrike — FBI Disrupts FAMOUS CHOLLIMA Operation with CrowdStrike Assistance (2026-10-13)](https://www.crowdstrike.com/en-us/blog/fbi-disrupts-famous-chollima-operation-with-crowdstrike-assistance/)
- [MITRE ATT&CK G0032 — Lazarus Group (parent cluster)](https://attack.mitre.org/groups/G0032/)
- [FBI IC3 Alert — North Korean IT Workers (2023)](https://www.ic3.gov/Media/Y2023/PSA231005)
- [CISA Advisory — North Korean IT Workers](https://www.cisa.gov/topics/cyber-threats-and-advisories/advanced-persistent-threats/north-korea)
