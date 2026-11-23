# GL.iNet GoodCloud Reverse Shell C2 (170.39.226.219)

## Description

Detects outbound reverse shell connections from GL.iNet routers and KVM devices compromised via the November 2026 GL.iNet GoodCloud cloud management API exploitation. Attackers abused an unspecified flaw in GL.iNet's cloud remote management service to push custom malware to enrolled devices; compromised devices beacon outbound to `170.39.226.219` with a persistent root-level reverse shell.

Each compromised device has a device-specific backdoor binary (hash-based detection is ineffective). The IOC-based rule fires immediately on any connection to the confirmed C2 IP. The behavioral rule detects reverse shells on common attacker-controlled ports from network device source categories.

**False positives (IOC rule):** None expected; `170.39.226.219` has no known legitimate purpose. **False positives (behavioral rule):** Authorized network testing, legitimate remote management tools using non-standard ports.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Command and Control |
| Tactic ID | TA0011 |
| Technique | Non-Application Layer Protocol |
| Technique ID | T1095 |
| Secondary Tactic | Persistence |
| Secondary Technique | Pre-OS Boot: System Firmware |
| Secondary Technique ID | T1542.001 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Command & Control (C2) |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_ip="170.39.226.219"
  by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.transport
     All_Traffic.app All_Traffic.bytes_out
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src_ip dest_ip dest_port transport app bytes_out risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.src_category IN ("router","network_appliance","firewall","kvm","iot")
    AND All_Traffic.dest_ip!="10.0.0.0/8"
    AND All_Traffic.dest_ip!="192.168.0.0/16"
    AND All_Traffic.dest_ip!="172.16.0.0/12"
    AND All_Traffic.dest_ip!="100.64.0.0/10"
    AND All_Traffic.dest_port IN ("4444","4445","5554","5555","6666","7777","8888","9999",
                                   "1234","1337","31337","2222","2323","4242","9001")
  by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.transport
     All_Traffic.bytes_out
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=75
| where risk_score >= 75
| table firstTime lastTime src_ip dest_ip dest_port transport bytes_out risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Any connection to 170.39.226.219 | 95 | Critical — confirmed GL.iNet GoodCloud reverse shell C2; no legitimate traffic expected |
| Outbound TCP from router/KVM/IoT device to common reverse shell ports | 75 | High — network infrastructure devices have no legitimate reason to initiate outbound connections on these ports |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unattributed (GL.iNet GoodCloud campaign, November 2026) | [BleepingComputer — GL.iNet GoodCloud](https://www.bleepingcomputer.com/news/security/hackers-exploit-glinet-cloud-flaw-to-infect-routers-kvm-devices/) |

## References

- [BleepingComputer — Hackers exploit GL.iNet cloud flaw to infect routers, KVM devices (2026-11-22)](https://www.bleepingcomputer.com/news/security/hackers-exploit-glinet-cloud-flaw-to-infect-routers-kvm-devices/)
- [GL.iNet Security Incident — November 20, 2026](https://www.gl-inet.com/security/)
- [Aviatrix Threat Research — GL.iNet GoodCloud](https://aviatrix.ai/threat-research-center/hackers-exploit-glinet-cloud-flaw-infect-routers-kvm-devices/)
- [MITRE ATT&CK — T1095 Non-Application Layer Protocol](https://attack.mitre.org/techniques/T1095/)
- [MITRE ATT&CK — T1133 External Remote Services](https://attack.mitre.org/techniques/T1133/)
- [MITRE ATT&CK — T1542.001 Pre-OS Boot: System Firmware](https://attack.mitre.org/techniques/T1542/001/)
