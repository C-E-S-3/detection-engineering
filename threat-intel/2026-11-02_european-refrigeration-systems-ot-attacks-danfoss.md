---
scraped_at: "2026-11-02T18:00:00Z"
source_url: "https://www.bleepingcomputer.com/news/security/hackers-disrupt-refrigeration-systems-at-european-supermarkets/"
report_type: threat-intel
severity: high
title: "European Supermarket Refrigeration Systems Targeted in OT Cyberattacks: Two Waves Hit France (Oct 11-12) and Seven EU Countries (Nov 1-2)"
---

# European Supermarket Refrigeration Systems Targeted in OT Cyberattacks

**Sources:** BleepingComputer, CERT-FR, AP/ITV news reporting, aicybr.com OT analysis  
**Wave 1 Date:** 2026-10-11 to 2026-10-12  
**Wave 2 Date:** 2026-11-01 to 2026-11-02  
**Severity:** High

---

## 1. IOCs

### Domains

No domains published. Attack leveraged direct internet exposure of management interfaces; no C2 domains identified in public reporting.

### IPs

No attacker IPs published. Attackers accessed management interfaces directly via the public internet from undisclosed source addresses.

### Hashes

No malware samples or file hashes published. The attack was operational manipulation via exposed management interfaces — no traditional malware deployment identified.

### CVEs / Vulnerabilities

| CVE / Vuln | Product | Description |
|-----------|---------|-------------|
| Unspecified (authentication bypass / default credentials) | Danfoss AK-SC255, AK-SC355, AK-PI 200, AK-PC 310 (EoL models) | Older Danfoss refrigeration supervisory controllers exposed on the public internet; end-of-life products no longer receiving firmware/security patches; attacked via exposed web management interface |

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | ID | Technique | Notes |
|--------|----|-----------|-------|
| Initial Access | TA0001 | T1133 — External Remote Services | Refrigeration management UIs exposed directly to the internet; no VPN or access control |
| Credential Access | TA0006 | T1110.001 — Brute Force: Password Guessing | Likely mechanism for controllers using default or weak credentials (not confirmed in public reporting) |
| Impact | TA0040 | T1565.001 — Stored Data Manipulation | Attackers altered refrigeration temperature setpoints and defrost cycle schedules stored in controller memory |
| Impact | TA0040 | T1489 — Service Stop | In some locations, refrigeration systems were disabled or set outside safe operating ranges, spoiling product |

**ICS ATT&CK (MITRE ATT&CK for ICS):**

| Tactic | ID | Technique | Notes |
|--------|----|-----------|-------|
| Impair Process Control | T0836 | Modify Parameter | Temperature and defrost schedule modification in refrigeration supervisory controllers |
| Impact | T0831 | Manipulation of Control | Direct manipulation of control set points via exposed management interface |

---

## 3. Malware & Tools

No malware deployed. Attackers used native management interface functionality:
- **Danfoss AK-EMP Tool** (web-based engineering UI) — legitimate management software abused over the internet
- Direct web UI access to supervisory controllers (AK-SC series system managers)

---

## 4. Threat Actor / Campaign Attribution

Attribution is **unconfirmed** in official public reporting. CERT-FR and law enforcement have not published verified attribution. Social media claims by hacktivist groups have not been independently verified.

**Wave 1 (Oct 11-12, 2026 — France):**
- CERT-FR issued a warning on 2026-10-12 about "numerous compromises" of internet-exposed refrigeration installation remote controllers
- Approximately 700 French supermarket locations reported disrupted refrigeration systems
- Affected units concentrated in older Danfoss products that had reached end-of-life
- Investigated as likely deliberate sabotage of food supply infrastructure

**Wave 2 (Nov 1-2, 2026 — Multi-country):**
- Attacks extended to supermarkets in at least 7 EU countries: **Belgium, Estonia, Finland, Ireland, Luxembourg, Netherlands, Sweden**
- Pentagon separately initiated an investigation into whether U.S. military commissaries using similar equipment might be at risk
- Retailers and suppliers began emergency review: applying available firmware patches, disconnecting vulnerable refrigeration equipment from public internet

---

## 5. Splunk Detection Searches

> See companion detection: [`ot_exposed_industrial_protocol_external_access.md`](../detections/impact/ot_exposed_industrial_protocol_external_access.md)

### 5.1 External IP Accessing ICS Protocol Ports

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.dest_port IN (102, 502, 20000, 4840, 44818, 47808, 2404, 1911, 9600)
  AND NOT (All_Traffic.src_ip IN ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"))
by All_Traffic.src_ip All_Traffic.dest All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.transport
| `drop_dm_object_name(All_Traffic)`
| eval protocol=case(
    dest_port=102,   "S7comm (Siemens S7)",
    dest_port=502,   "Modbus TCP",
    dest_port=20000, "DNP3",
    dest_port=4840,  "OPC-UA",
    dest_port=44818, "EtherNet/IP",
    dest_port=47808, "BACnet/IP",
    dest_port=2404,  "IEC 60870-5-104",
    dest_port=1911,  "Tridium Niagara Fox",
    dest_port=9600,  "OMRON FINS",
    1=1, "Unknown")
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime src_ip dest dest_ip dest_port protocol transport count
```

### 5.2 Web Management Access to Danfoss / Industrial Refrigeration Controllers (Proxy Logs)

```spl
index=web_proxy OR index=zeek_http
(url="*/AK-SC*" OR url="*/AK-EMP*" OR url="*/danfoss*" OR url="*/refrigeration*" OR url="*/setpoint*" OR url="*/defrost*")
AND NOT (src_ip IN ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
| eval risk_score=case(
    match(url, "setpoint|defrost|schedule"), 95,
    match(url, "AK-SC|AK-EMP|danfoss"), 85,
    1=1, 70)
| where risk_score >= 70
| table _time src_ip dest url status risk_score
```

---

## 6. Executive Summary

In two coordinated waves, attackers disrupted refrigeration systems at supermarkets across Europe by directly accessing internet-exposed OT management interfaces on Danfoss refrigeration supervisory controllers. The first wave (October 11-12) hit approximately 700 French supermarket locations; CERT-FR issued an advisory the same day. The second wave (November 1-2) expanded to Belgium, Estonia, Finland, Ireland, Luxembourg, Netherlands, and Sweden.

The attack required no malware: older Danfoss AK-SC series controllers — which reached end-of-life and no longer receive firmware security patches — were left reachable from the public internet, in many cases protected only by default or weak credentials. Attackers modified temperature setpoints and defrost schedules through the native web management interface, disrupting food storage in affected locations.

**Key OT security failure:** Direct internet exposure of management interfaces with no VPN, firewall restriction, or modern authentication on end-of-life industrial equipment. This attack pattern — exploiting internet-facing OT management UIs without malware deployment — is repeatable against any sector using legacy industrial controllers with public-facing web management.

---

## 7. References

- [CERT-FR Warning — October 12, 2026 (FR)](https://www.cert.ssi.gouv.fr/)
- [BleepingComputer — Hackers disrupt refrigeration systems at European supermarkets (2026-11-02)](https://www.bleepingcomputer.com/news/security/hackers-disrupt-refrigeration-systems-at-european-supermarkets/)
- [ITV News — Freezers at supermarkets across Europe hit by apparent cyberattacks (2026-11-02)](https://www.itv.com/news/2026-11-02/freezers-at-supermarkets-across-europe-hit-by-apparent-cyberattacks)
- [aicybr.com — Europe's Supermarket Freezer Incidents: OT Security After Suspected Cyberattacks](https://aicybr.com/blog/europe-supermarket-freezer-incidents-ot-security-november-2026)
- [CXO Digital Pulse — Supermarket Refrigeration Systems Targeted in Cyberattacks Across Seven European Countries](https://www.cxodigitalpulse.com/?p=64531)
- [MITRE ATT&CK ICS — T0831: Manipulation of Control](https://attack.mitre.org/techniques/T0831/)
- [MITRE ATT&CK — T1133: External Remote Services](https://attack.mitre.org/techniques/T1133/)
- [Danfoss AK-SC Series EoL Notice](https://www.danfoss.com/en/service-and-support/product-support/end-of-life-products/)
