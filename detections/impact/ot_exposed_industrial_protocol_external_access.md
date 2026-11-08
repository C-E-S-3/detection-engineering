# OT Exposed Industrial Protocol External Access

## Description

Detects inbound connections from internet-routable (non-RFC1918) source IP addresses to internal hosts on ports associated with industrial control system (ICS/OT/SCADA) protocols. This pattern indicates that operational technology management interfaces are either directly internet-exposed or are being accessed from unexpected external sources, which is the attack vector used in the November 2026 European supermarket refrigeration attacks.

Legitimate traffic on these ports originates exclusively from internal engineering workstations, OT jump servers, or site-to-site VPN tunnels. External source IPs reaching these ports directly indicates a network segmentation failure or active exploitation.

**False positives:** Industrial remote monitoring services (some vendors offer cloud-hosted HMI relay services) may appear as external IPs connecting to these ports. Validate against approved vendor remote monitoring contracts before suppressing.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Impact |
| Tactic ID | TA0040 |
| Technique | Manipulation of Control (ICS) / Stored Data Manipulation |
| Technique ID | T1565.001 (Enterprise); T0831 (ICS ATT&CK) |
| Secondary Tactic | Initial Access (TA0001) |
| Secondary Technique | T1133 — External Remote Services |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Actions on Objectives |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.dest_port IN (102, 502, 20000, 4840, 44818, 47808, 2404, 1911, 9600, 10307, 20547, 34980)
  AND NOT (All_Traffic.src_ip IN ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8"))
by All_Traffic.src_ip All_Traffic.dest All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.transport All_Traffic.bytes
| `drop_dm_object_name(All_Traffic)`
| eval protocol=case(
    dest_port=102,   "S7comm — Siemens S7 PLC",
    dest_port=502,   "Modbus TCP",
    dest_port=20000, "DNP3",
    dest_port=4840,  "OPC-UA",
    dest_port=44818, "EtherNet/IP",
    dest_port=47808, "BACnet/IP",
    dest_port=2404,  "IEC 60870-5-104",
    dest_port=1911,  "Tridium Niagara Fox",
    dest_port=9600,  "OMRON FINS",
    dest_port=10307, "GE-SRTP",
    dest_port=20547, "ProConOS",
    dest_port=34980, "EtherNet/IP over UDP",
    1=1, "Unknown ICS Port")
| eval risk_score=case(
    dest_port IN (102, 502, 20000, 44818), 95,
    dest_port IN (4840, 47808, 2404, 1911, 9600), 80,
    1=1, 70)
| where risk_score >= 70
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime src_ip dest dest_ip dest_port protocol transport bytes count risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| External IP to Modbus (502), S7comm (102), DNP3 (20000), or EtherNet/IP (44818) | 95 | These are process-level fieldbus protocols used to directly read/write controller I/O and setpoints; external access is never legitimate in a properly segmented OT network |
| External IP to OPC-UA (4840), BACnet (47808), IEC 60870-5-104 (2404), Niagara Fox (1911), OMRON FINS (9600) | 80 | Supervisory and building/energy management protocols; often used for HVAC, refrigeration, and BMS management; external access indicates internet-exposed management interface |
| External IP to other identified ICS ports | 70 | Anomalous but requires context |

## Associated Threat Actors

| Actor | Technique | References |
|-------|-----------|-----------|
| Unknown (European Refrigeration Attacks, Oct-Nov 2026) | Manipulation of internet-exposed Danfoss refrigeration supervisory controllers via web UI; altered temperature setpoints and defrost schedules | [BleepingComputer (2026-11-02)](https://www.bleepingcomputer.com/news/security/hackers-disrupt-refrigeration-systems-at-european-supermarkets/), [CERT-FR (2026-10-12)](https://www.cert.ssi.gouv.fr/) |
| XENOTIME (Triton/TRISIS) | Manipulation of Safety Instrumented Systems via engineering workstation access | [MITRE ATT&CK ICS — XENOTIME](https://attack.mitre.org/groups/G0088/) |
| Sandworm (Industroyer/CRASHOVERRIDE) | ICS protocol abuse (IEC 60870-5-101/104, IEC 61850, GOOSE) for power grid impact | [MITRE ATT&CK — Sandworm (G0034)](https://attack.mitre.org/groups/G0034/) |

## References

- [MITRE ATT&CK ICS — T0831: Manipulation of Control](https://attack.mitre.org/techniques/T0831/)
- [MITRE ATT&CK — T1133: External Remote Services](https://attack.mitre.org/techniques/T1133/)
- [MITRE ATT&CK — T1565.001: Stored Data Manipulation](https://attack.mitre.org/techniques/T1565/001/)
- [CISA — Recommended Practices for Industrial Control System Security](https://www.cisa.gov/topics/industrial-control-systems)
- [Threat Intel: 2026-11-02 European Refrigeration OT Attacks](../../threat-intel/2026-11-02_european-refrigeration-systems-ot-attacks-danfoss.md)
- [ICS-CERT Advisory on Remote Access to ICS](https://www.cisa.gov/news-events/ics-advisories)
