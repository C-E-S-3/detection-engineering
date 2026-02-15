# Kerberos Anomaly Detection - TTPs and Analysis

## Overview

Kerberos is the default authentication protocol in Windows Active Directory environments, used to verify the identity of users and hosts through a ticket-based system. Because of its central role, Kerberos is a frequent target for adversaries seeking to steal, forge, or abuse authentication tickets for lateral movement, persistence, and privilege escalation.

This detection pack focuses on identifying suspicious Kerberos behavior by analyzing **TGT TicketOptions flags**, **encryption type downgrades**, **anomalous request volumes**, and **tool-specific fingerprints** from offensive frameworks such as Rubeus, Impacket, Mimikatz, and Metasploit.

**Primary Reference:** [NVISO - Hunting Kerberos: Decode TGT TicketOptions with KQL](https://blog.nviso.eu/2026/02/12/capture-the-kerberos-flag-detecting-kerberos-anomalies/) by Thomas Papaloukas (February 2026)

---

## Kerberos TicketOptions Flag Encoding

Kerberos ticket options use **MSB 0 (Most Significant Bit)** bit numbering for a 32-bit field. Bits are numbered 0 (MSB) through 31 (LSB), left to right. Each bit corresponds to a specific flag:

| Bit | Flag Name | Hex Contribution | Description |
|-----|-----------|-----------------|-------------|
| 0 | Reserved | `0x80000000` | Reserved |
| 1 | Forwardable | `0x40000000` | Ticket can be forwarded to another host |
| 2 | Forwarded | `0x20000000` | Ticket has been forwarded |
| 3 | Proxiable | `0x10000000` | Ticket can be used to obtain proxy tickets |
| 4 | Proxy | `0x08000000` | Ticket is a proxy ticket |
| 5 | Allow-postdate | `0x04000000` | Ticket can be postdated |
| 6 | Postdated | `0x02000000` | Ticket is postdated |
| 7 | Invalid | `0x01000000` | Ticket is invalid (needs validation) |
| 8 | Renewable | `0x00800000` | Ticket can be renewed |
| 9 | Initial | `0x00400000` | This is the initial ticket (AS-REP) |
| 10 | Pre-authent | `0x00200000` | Pre-authenticated |
| 11 | Opt-hw-auth | `0x00100000` | Hardware authentication was used |
| 15 | Canonicalize | `0x00010000` | KDC can modify client/server principal names |
| 26 | Disable-transited-check | `0x00000020` | Transited checking disabled |
| 27 | Renewable-ok | `0x00000010` | Renewable ticket accepted |
| 28 | Enc-tkt-in-skey | `0x00000008` | Encrypt ticket in session key |
| 30 | Renew | `0x00000002` | Renewal request |
| 31 | Validate | `0x00000001` | Validate postdated ticket |

---

## Tool-Specific TicketOptions Fingerprints

A critical insight from the NVISO research is that offensive tools produce **distinct TicketOptions hex values** that deviate from normal Windows behavior. The most important anomaly is the **absence of the Canonicalize flag (bit 15)**.

| Hex Value | Flags Set | Tool(s) | Detection Notes |
|-----------|-----------|---------|-----------------|
| `0x40810010` | Forwardable, Renewable, Canonicalize, Renewable-ok | **Legitimate Windows (baseline)** | Standard TGT request from Windows clients |
| `0x40800010` | Forwardable, Renewable, Renewable-ok | **Rubeus, Impacket, Certipy, Whisker** | Missing Canonicalize (bit 15) - hardcoded in Rubeus source |
| `0x50800000` | Forwardable, Proxiable, Renewable | **Metasploit** | Unusual Proxiable flag + missing Canonicalize |
| `0x40800000` | Forwardable, Renewable | **Rubeus (kerberoast)** | Minimal flags, missing Canonicalize + Renewable-ok |
| `0x40810000` | Forwardable, Renewable, Canonicalize | **Modified Impacket** | Missing Renewable-ok, otherwise mimics legitimate |

### Why the Missing Canonicalize Flag Matters

The **name-canonicalize** flag (bit 15) allows the KDC to map multiple principal names and SPNs. Legitimate Windows clients **always** set this flag. Offensive tools like Rubeus have this flag **deliberately omitted** in their hardcoded ticket options. This makes `Canonicalize = absent` a high-fidelity detection signal for tooling including:

- Rubeus (all operations)
- Impacket (GetUserSPNs.py, getTGT.py, getST.py)
- Certipy (ADCS exploitation)
- Whisker (Shadow Credentials)

---

## Kerberos Encryption Types

| Hex Value | Decimal | Encryption Type | Detection Relevance |
|-----------|---------|----------------|-------------------|
| `0x17` | 23 | RC4-HMAC | Weak - commonly used in Kerberoasting, Golden/Silver Ticket, OverPass-the-Hash |
| `0x12` | 18 | AES256-CTS-HMAC-SHA1 | Strong - standard in modern environments |
| `0x11` | 17 | AES128-CTS-HMAC-SHA1 | Strong - standard in modern environments |
| `0x03` | 3 | DES-CBC-MD5 | Deprecated - highly suspicious |
| `0x01` | 1 | DES-CBC-CRC | Deprecated - highly suspicious |

RC4 encryption (`0x17`) in Kerberos requests is a key indicator because attackers prefer it for offline cracking — it is significantly faster to brute-force than AES.

---

## Attack Techniques Covered

### 1. Suspicious TGT TicketOptions (Tool Fingerprinting)
**MITRE ATT&CK:** T1558 - Steal or Forge Kerberos Tickets
**Event ID:** 4768
**Description:** Detect TGT requests containing TicketOptions hex values associated with known offensive tools. Focus on the absence of the Canonicalize flag and presence of unusual flag combinations.

### 2. Kerberoasting
**MITRE ATT&CK:** T1558.003 - Kerberoasting
**Event ID:** 4769
**Description:** Detect Kerberos TGS requests with RC4 encryption targeting service accounts. Kerberoasting tools request service tickets for accounts with SPNs and crack them offline.

### 3. AS-REP Roasting
**MITRE ATT&CK:** T1558.004 - AS-REP Roasting
**Event ID:** 4768
**Description:** Detect TGT requests for accounts with Kerberos pre-authentication disabled, especially when combined with RC4 encryption.

### 4. Golden Ticket
**MITRE ATT&CK:** T1558.001 - Golden Ticket
**Event ID:** 4768, 4769
**Description:** Detect forged TGTs by identifying RC4-encrypted TGT requests and TGS requests that lack a preceding legitimate TGT event.

### 5. OverPass-the-Hash
**MITRE ATT&CK:** T1550.002 - Pass the Hash
**Event ID:** 4768
**Description:** Detect TGT requests using RC4 encryption (0x17), which may indicate an adversary using a stolen NTLM hash to obtain a Kerberos ticket.

### 6. Anomalous Kerberos Request Volume
**MITRE ATT&CK:** T1558.003 - Kerberoasting
**Event ID:** 4769
**Description:** Detect an unusual volume of service ticket requests from a single account, which is characteristic of Kerberoasting or service enumeration.

### 7. Kerberos Pre-Authentication Brute Force
**MITRE ATT&CK:** T1110.001 - Brute Force: Password Guessing
**Event ID:** 4771
**Description:** Detect brute force or password spraying attacks against Kerberos pre-authentication by monitoring failed TGT requests.

---

## Prerequisites

To successfully use these detections, the following audit policies must be enabled on **all Domain Controllers**:

1. **Audit Kerberos Authentication Service** (Success/Failure) - generates Event ID 4768 and 4771
2. **Audit Kerberos Service Ticket Operations** (Success/Failure) - generates Event ID 4769 and 4770

These are configured under:
`Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Account Logon`

---

## Tuning Recommendations

1. **Baseline your environment** - Collect TicketOptions values for 7-14 days to understand normal flag combinations before alerting.
2. **Exclude known service accounts** - Some legacy systems (e.g., NetApp, older Linux/Unix Kerberos clients) may legitimately use RC4 or unusual TicketOptions.
3. **Filter machine accounts** - Service ticket requests where `ServiceName` ends with `$` are typically machine-to-machine and can be filtered for Kerberoasting detections.
4. **Monitor encryption policy** - If RC4 is disabled via Group Policy, any RC4 request is immediately suspicious and should be high-priority.

---

## References

- [NVISO - Hunting Kerberos: Decode TGT TicketOptions with KQL](https://blog.nviso.eu/2026/02/12/capture-the-kerberos-flag-detecting-kerberos-anomalies/)
- [Splunk - Detecting Active Directory Kerberos Attacks (March 2022)](https://www.splunk.com/en_us/blog/security/detecting-active-directory-kerberos-attacks-threat-research-release-march-2022.html)
- [Splunk Security Content - Kerberoasting SPN Request with RC4](https://research.splunk.com/endpoint/5cc67381-44fa-4111-8a37-7a230943f027/)
- [Splunk Security Content - Kerberos TGT Request Using RC4](https://research.splunk.com/endpoint/18916468-9c04-11ec-bdc6-acde48001122/)
- [ADSecurity - Detecting Kerberoasting Activity](https://adsecurity.org/?p=3458)
- [TrustedSec - The Art of Bypassing Kerberoast Detections with Orpheus](https://trustedsec.com/blog/the-art-of-bypassing-kerberoast-detections-with-orpheus)
- [Kaspersky Securelist - Anomaly Detection in Certificate-Based TGT Requests](https://securelist.com/anomaly-detection-in-certificate-based-tgt-requests/110242/)
- [Microsoft - Event 4768 Documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [Microsoft - Event 4769 Documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
