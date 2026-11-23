---
scraped_at: 2026-11-23T08:00:00Z
source_url: https://www.bleepingcomputer.com/news/security/hackers-exploit-glinet-cloud-flaw-to-infect-routers-kvm-devices/
report_type: threat-intel
severity: high
title: "GL.iNet GoodCloud Cloud Management Flaw Exploited to Install Backdoors on Routers and KVM Devices"
---

## 1. IOCs

### IP Addresses

| IP | Description |
|----|-------------|
| `170.39.226.219` | Reverse shell C2 server — compromised GL.iNet routers and KVM devices beacon to this IP |

### File Hashes

None published. Each compromised router carries its own build of the backdoor binary (device-specific); hash-based detection is not effective.

### Domains / IPs

No domain IOCs published. Attribution of `170.39.226.219` to this campaign confirmed by RemoteToHome Consulting incident response analysis.

---

## 2. TTPs

| MITRE Tactic | Technique ID | Technique Name | Usage |
|---|---|---|---|
| Initial Access | T1190 | Exploit Public-Facing Application | Exploitation of unspecified flaw in GL.iNet GoodCloud cloud remote management API; allowed attackers to authenticate as the target device or cloud management service |
| Initial Access | T1133 | External Remote Services | GL.iNet GoodCloud is a cloud-to-device management channel; attackers abused this legitimate remote management channel to reach on-premises devices from the internet |
| Execution | T1059.004 | Unix Shell | Root-level shell execution on compromised routers and KVM devices via cloud management API |
| Persistence | T1543.003 | Create or Modify System Process | Custom backdoor binary installed as a persistent service/daemon on router firmware; each device receives a device-specific build |
| Command and Control | T1095 | Non-Application Layer Protocol | Reverse shell from compromised devices to 170.39.226.219 on non-HTTP port |
| Lateral Movement | T1021.001 | Remote Desktop Protocol | KVM (keyboard/video/mouse over IP) devices compromised; physical console access to connected systems at risk |
| Persistence | T1542.001 | Pre-OS Boot: System Firmware | Router-level backdoor survives standard OS reset; GL.iNet's integrity check does NOT detect the installed backdoor; full firmware flash required for remediation |
| Defense Evasion | T1036 | Masquerading | Device-specific backdoor builds prevent hash-based detection; older backdoor infections (47/183 routers in one survey) may predate the November incident |

---

## 3. Malware & Tools

### GL.iNet GoodCloud Router Backdoor

Custom malware written specifically for GL.iNet router and KVM device architecture (MIPS/ARM Linux). Key characteristics:

- **Device-specific builds:** Each compromised device has its own binary; hash lists are ineffective for detection.
- **Reverse shell to 170.39.226.219:** Persistent outbound connection providing the attacker an interactive root shell.
- **Survives GL.iNet integrity check:** The vendor-provided integrity verification tool does NOT detect the installed backdoor. Full firmware reflash is required.
- **Older backdoor variant:** RemoteToHome Consulting found a second, older backdoor pre-installed on 47 of 183 surveyed routers since at least Saturday November 15, 2026. This older variant may be unrelated to the November 2026 GoodCloud exploitation.
- **KVM risk:** Attackers with control of network KVM devices have physical-equivalent access to servers connected via KVM; any system managed via a compromised GL.iNet KVM must be treated as potentially compromised.

### GL.iNet GoodCloud

Legitimate cloud remote management service operated by GL.iNet Technologies. The API vulnerability allowed unauthenticated or maliciously authenticated attackers to push malware to enrolled devices over the cloud management channel — an attacker-controlled "supply chain" of the cloud management plane.

---

## 4. Threat Actor / Campaign Attribution

| Attribute | Value |
|---|---|
| Attribution | Unknown; unattributed as of November 22, 2026 |
| Disclosure | GL.iNet confirmed the incident November 20, 2026 |
| Scope | Multiple GL.iNet routers and KVM devices; number of affected customers undisclosed |
| Tactical pattern | Cloud management API abuse for on-premises hardware compromise; similar to attacks on other cloud-managed network device ecosystems (Netgear Armor, Asus AiProtection, TP-Link HomeCare) |

GL.iNet stated the cloud-side vulnerability has been patched and the attack path has been blocked. However, **malware already installed on devices is not removed**; a firmware update with enhanced integrity protections was planned for November 22, 2026.

---

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_ip="170.39.226.219"
  by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.transport
     All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src_ip dest_ip dest_port transport app risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.src_category IN ("router","network-appliance","firewall","kvm") OR
        All_Traffic.transport="tcp"
  by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.transport
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| lookup dns_records ip as dest_ip OUTPUT domain as dest_domain
| where isnull(dest_domain) AND dest_ip!="10.0.0.0/8" AND dest_ip!="192.168.0.0/16"
       AND dest_ip!="172.16.0.0/12" AND dest_port IN ("4444","4445","5555","6666","7777","8888","9999","1234","31337")
| eval risk_score=75
| where risk_score >= 75
| table firstTime lastTime src_ip dest_ip dest_port transport risk_score
```

---

## 6. Executive Summary

On November 20, 2026, GL.iNet confirmed that an unspecified vulnerability in its GoodCloud cloud remote management service was exploited to install custom malware on routers and KVM (keyboard/video/mouse over IP) devices. The attack vector is the cloud-to-device management channel — attackers abused the cloud API to push malware directly to enrolled on-premises hardware, bypassing traditional network perimeter controls.

Compromised devices beacon outbound to the reverse shell C2 server `170.39.226.219`. Each device receives a device-specific backdoor binary, making hash-based detection ineffective. Critically, **GL.iNet's own integrity check tool does not detect the installed backdoor**, and **cloud-side patching does not remove malware from already-infected devices** — full firmware reflash is the only remediation.

For organizations using GL.iNet devices (travel routers, branch office routers, remote-site KVM units): assume compromise if enrolled in GoodCloud, quarantine affected devices, reflash firmware from a trusted source, and rotate credentials on any systems physically connected to compromised KVM units.

The novel attack pattern — cloud management plane exploitation to deliver hardware-resident malware — is a significant threat model escalation for cloud-managed network device ecosystems. Organizations should audit all network devices enrolled in vendor cloud management services and restrict those cloud management channels where not operationally required.
