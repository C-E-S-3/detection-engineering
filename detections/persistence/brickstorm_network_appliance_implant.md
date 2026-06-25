# BRICKSTORM In-Memory Backdoor on Network Appliances

## Description

Detects behavioral indicators of BRICKSTORM, a custom in-memory backdoor deployed on edge network appliances (routers, firewalls, VPN concentrators) by Chinese-nexus espionage actors UNC6201 and UNC5807. BRICKSTORM achieves extreme persistence by living entirely in memory on network devices — it survives reboots via modified initialization scripts and leaves no traditional disk artifacts for AV/EDR to detect. The implant provides persistent backdoor access and can intercept credentials via native packet-capture functionality on the appliance. Observed targeting: enterprise edge devices (Ivanti, Fortinet, Cisco), with lateral movement into core network infrastructure. Primary detection surface: syslog from managed network appliances, NetFlow/PCAP anomalies, and unexpected CLI commands via management plane logs. Common false positives: legitimate vendor diagnostics and authorized remote debugging sessions; baseline expected management-plane connections and alert on deviations.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Persistence |
| Tactic ID | TA0003 |
| Technique | Server Software Component: Web Shell |
| Technique ID | T1505.003 |

Secondary techniques: T1556.004 (Modify Authentication Process: Network Device Authentication — packet sniffing for credential interception), T1601.001 (Modify System Image: Patch System Image — modified init scripts), T1040 (Network Sniffing — passive credential capture), T1027.011 (Obfuscated Files or Information: Fileless Storage — memory-only implant)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Installation |
| Command & Control (C2) |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.src_category="network_appliance"
    AND All_Traffic.dest_port IN (443, 80, 8443, 8080, 4444, 9001, 9030)
    AND NOT (All_Traffic.dest_ip IN (rfc1918_subnets) OR All_Traffic.dest_ip IN (known_management_ips))
  by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port
     All_Traffic.bytes_out All_Traffic.bytes_in
| `drop_dm_object_name(All_Traffic)`
| eval beacon_ratio=round(bytes_out/if(bytes_in>0,bytes_in,1), 2)
| eval risk_score=case(
    bytes_out > 1000000 AND beacon_ratio > 5, 85,
    dest_port IN (4444, 9001, 9030), 90,
    bytes_out > 500000, 70,
    1=1, 50)
| where risk_score >= 70
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime src_ip dest_ip dest_port bytes_out bytes_in beacon_ratio risk_score
```

**Supplemental: Unexpected management-plane CLI commands from network devices (syslog)**

```spl
index=network_devices sourcetype IN ("cisco_ios", "fortinet", "opnsense", "pfsense")
| regex _raw="(python|perl|curl|wget|bash|sh\s+-c|exec|/tmp/|chmod\s+[0-7]+x|mkfifo)"
| eval risk_score=case(
    match(_raw, "(?i)curl|wget|python.*http|perl.*http"), 85,
    match(_raw, "(?i)/tmp/\S+\s+&|mkfifo|bash\s+-i"), 90,
    match(_raw, "(?i)chmod.*\+x|exec\s+[0-9]+<>"), 80,
    1=1, 70)
| where risk_score >= 70
| stats count min(_time) as firstTime max(_time) as lastTime
        values(_raw) as cmd_samples by host, risk_score
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime host cmd_samples risk_score
```

**Supplemental: Packet capture/sniffing activity on network appliance management interface**

```spl
index=network_devices sourcetype IN ("cisco_ios", "fortinet", "opnsense", "pfsense")
| regex _raw="(?i)(tcpdump|pcap|packet.capture|debug.*packet|monitor.*capture|tshark)"
| eval risk_score=case(
    match(_raw, "(?i)tcpdump.*-w|pcap.*output"), 80,
    match(_raw, "(?i)monitor.*capture.*start"), 75,
    1=1, 65)
| where risk_score >= 75
| stats count min(_time) as firstTime max(_time) as lastTime
        values(_raw) as cmd_samples by host, risk_score
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime host cmd_samples risk_score
```

**Supplemental: Periodic beaconing pattern from network appliance (time-delta analysis)**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
        values(All_Traffic.dest_ip) as destinations
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.src_category="network_appliance"
  by All_Traffic.src_ip _time span=1h
| `drop_dm_object_name(All_Traffic)`
| stats count as hourly_connections stdev(count) as connection_jitter
        min(firstTime) as firstTime max(lastTime) as lastTime by src_ip
| eval beacon_regularity=case(connection_jitter < 2 AND hourly_connections > 10, "HIGH",
                               connection_jitter < 5 AND hourly_connections > 5, "MEDIUM",
                               1=1, "LOW")
| where beacon_regularity="HIGH"
| eval risk_score=90
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime src_ip hourly_connections connection_jitter beacon_regularity risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Network appliance connecting to non-RFC1918, non-management IP on atypical port (4444, 9001, 9030) | 90 | Classic C2 port; no legitimate reason for network appliance to initiate these connections |
| Network appliance connecting to external IP with large asymmetric outbound data | 85 | BRICKSTORM exfiltrates credential captures; high bytes_out with low bytes_in = likely exfil |
| Shell/interpreter commands in network device syslog | 80–90 | BRICKSTORM drops scripts via modified init; interpreter invocation from managed device is anomalous |
| Packet capture commands on management interface | 75–80 | BRICKSTORM uses native pcap to intercept credentials; legitimate capture should be authorized |
| Highly regular beaconing (low jitter, consistent hourly pattern) | 90 | BRICKSTORM heartbeat pattern; legitimate appliance traffic has higher jitter |

## Associated Threat Actors

| Actor | Relationship to Detection |
|-------|--------------------------|
| UNC6201 | Chinese-nexus espionage group; deploys BRICKSTORM on network appliances for persistent access; identified in M-Trends 2026 as targeting edge and core network devices |
| UNC5807 | Chinese-nexus espionage group; co-attributed with BRICKSTORM deployment on edge network devices; targets enterprise core network infrastructure |

## References

- [Google M-Trends 2026](https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026/)
- [MITRE ATT&CK - T1505.003 Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003/)
- [MITRE ATT&CK - T1556.004 Modify Authentication Process: Network Device Authentication](https://attack.mitre.org/techniques/T1556/004/)
- [MITRE ATT&CK - T1040 Network Sniffing](https://attack.mitre.org/techniques/T1040/)
