# PAN-OS Captive Portal RCE Exploitation (CVE-2026-0300)

## Description

Detects exploitation of CVE-2026-0300, a critical (CVSS 9.3) heap buffer overflow in the Palo Alto Networks PAN-OS User-ID Authentication Portal (Captive Portal) affecting PAN-OS 10.2, 11.1, 11.2, and 12.1 on PA-Series and VM-Series firewalls. An unauthenticated attacker delivers a single crafted packet to trigger the overflow and execute arbitrary code as root.

Unit 42 attributes active exploitation to **CL-STA-1132**, a likely state-sponsored cluster that began exploitation on April 9, 2026 — a month before public disclosure. Post-exploitation activity includes dropping EarthWorm and ReverseSocks5 tunneling tools to `/var/tmp/` and `/tmp/`, Active Directory enumeration using credentials harvested from the firewall, and systematic log destruction.

This detection has two complementary searches:
1. **IOC-based**: outbound connections from any host to confirmed CL-STA-1132 C2/staging IPs.
2. **Behavioral**: unexpected outbound SOCKS/proxy-port traffic originating from the perimeter firewall segment — a strong signal of firewall compromise regardless of known IOCs.

False positives on the behavioral search: legitimate SOCKS5 proxy or jump-server activity on the firewall management interface. Tune `All_Traffic.src_category` to match your CMDB classification for PAN-OS appliances.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |

Secondary techniques (post-exploitation): T1572 (Protocol Tunneling — EarthWorm/ReverseSocks5), T1070.002 (Indicator Removal: Clear Linux Logs), T1018 (Remote System Discovery).

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Delivery |
| Exploitation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_ip IN ("67.206.213.86","136.0.8.48","146.70.100.69","149.104.66.84")
  by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.action
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src_ip dest_ip dest_port action risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.src_category="perimeter_firewall"
    All_Traffic.dest_port IN ("1080","8000","9999","4444")
    All_Traffic.action="allowed"
  by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.bytes_out
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    dest_port="4444" OR dest_port="9999", 90,
    dest_port="1080", 80,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime src_ip dest_ip dest_port bytes_out risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Connection to confirmed CL-STA-1132 C2 IP (67.206.213.86, 136.0.8.48, 146.70.100.69, 149.104.66.84) | 95 | Direct IOC match; near-certain true positive |
| Firewall-segment source connecting outbound on port 4444 or 9999 | 90 | Common reverse-shell and proxy ports; no legitimate use from firewall management segment |
| Firewall-segment source connecting outbound on port 1080 (SOCKS) | 80 | SOCKS proxy from firewall itself is anomalous; consistent with EarthWorm/ReverseSocks5 |
| Firewall-segment source connecting outbound on port 8000 | 70 | Dev HTTP port; consistent with EarthWorm download server (146.70.100.69:8000/php_sess) |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| CL-STA-1132 (state-sponsored, nexus unconfirmed) | [Unit 42 — PAN-OS Captive Portal Zero-Day Threat Brief](https://unit42.paloaltonetworks.com/captive-portal-zero-day/), [Palo Alto Networks CVE-2026-0300](https://security.paloaltonetworks.com/CVE-2026-0300) |

## References

- [Unit 42 Threat Brief: CVE-2026-0300](https://unit42.paloaltonetworks.com/captive-portal-zero-day/)
- [Palo Alto Networks Security Advisory CVE-2026-0300](https://security.paloaltonetworks.com/CVE-2026-0300)
- [MITRE ATT&CK T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK T1572 — Protocol Tunneling](https://attack.mitre.org/techniques/T1572/)
- [BleepingComputer — PAN-OS Firewall RCE Zero-Day](https://www.bleepingcomputer.com/news/security/palo-alto-networks-warns-of-actively-exploited-firewall-zero-day/)
