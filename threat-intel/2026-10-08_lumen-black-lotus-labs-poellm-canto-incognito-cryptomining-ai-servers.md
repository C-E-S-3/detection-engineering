---
scraped_at: "2026-10-08T12:00:00Z"
source_url: "https://www.lumen.com/blog/en-us/canto-incognito-tracking-the-poellm-malware"
report_type: threat-intel
severity: high
title: "PoeLLM / Canto Incognito: Cryptomining Botnet Targets Exposed AI Servers via GitHub Poem C2 Steganography"
---

## 1. Indicators of Compromise (IOCs)

### C2 IP Addresses

| IP Address | Status (as of 2026-10-07) | Date Range Observed |
|------------|--------------------------|---------------------|
| `92.119.164[.]50` | **Active** | 2026 campaign |
| `103.249.201[.]108` | **Active** | 2026 campaign |
| `178.128.14[.]204` | **Active** | 2026 campaign |
| `191.37.28.160` | Historical | 2026-04-13 – 2026-05-16 |
| `89.39.253.46` | Historical | 2026-04-14 – 2026-06-24 |
| `120.224.114.212` | Historical | 2026-05-09 – 2026-09-08 |
| `5.78.73.122` | Historical | 2026-06-08 – 2026-08-22 |
| `15.204.178.28` | Historical | 2026-06-14 – 2026-08-17 |
| `92.119.165.74` | Historical | 2026-07-01 – 2026-07-23 |

C2 infrastructure communicates over ports **3778, 5001, 5002, and 9999**. Initial payload delivery observed over port 81.

### C2 Steganography — GitHub Repository

| Indicator | Type | Notes |
|-----------|------|-------|
| `github.com/ejejejdfbbebe` | GitHub account | Account hosting the poem used for C2 IP encoding |
| First poem commit: 2026-04-13; 11+ updates observed through report date | Timeline | Operator rotates C2 IPs by editing the poem |

### Malware Infrastructure Domain

| Domain (defanged) | Notes |
|-------------------|-------|
| `malwarescan[.]xyz` | Infrastructure domain associated with campaign; registered early in the campaign (server: 57.131.5[.]211) |

### CVEs Exploited

| CVE | CVSS | Affected Software | Notes |
|-----|------|-------------------|-------|
| CVE-2026-42271 | High | LiteLLM versions 1.74.2 – <1.83.7 | Authenticated (low-privilege API key) RCE via malicious MCP configuration in the `/mcp-rest/test/connection` endpoint; exploited by PoeLLM to compromise LiteLLM servers |
| CVE-2026-10520 | High | Ivanti Sentry | At least one Ivanti Sentry compromise observed reaching PoeLLM C2 infrastructure; initial discovery vector |

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique | ID | Usage |
|--------|-----------|----|-------|
| Initial Access | Exploit Public-Facing Application | T1190 | Exploits CVE-2026-42271 (LiteLLM MCP RCE) and CVE-2026-10520 (Ivanti Sentry) against internet-exposed AI and developer servers |
| Discovery | Network Service Discovery | T1046 | Infected hosts repurposed as botnet scanners; scan ports 3000 (LiteLLM/Gotenberg) and 4000 (LiteLLM) seeking new victims |
| Execution | Command and Scripting Interpreter: Unix Shell | T1059.004 | ELF malware (`libgcrypt`) executes shell commands for persistence, miner deployment, and botnet expansion |
| Persistence | Boot or Logon Autostart Execution | T1037 | Malware deploys XMRig/Iron miners with persistence to survive reboots |
| Command and Control | Web Service: Dead Drop Resolver | T1102.001 | C2 IPv4 address encoded into a GitHub-hosted poem; malware extracts specific words, maps them through a hard-coded dictionary to an IP; IP is rotated by editing the poem |
| Command and Control | Non-Standard Port | T1571 | C2 communications over ports 3778, 5001, 5002, and 9999 |
| Impact | Resource Hijacking | T1496 | Deploys XMRig and Iron cryptocurrency miners; routes mining output to Kryptex (Russian mining pool) |
| Lateral Movement | Exploit Public-Facing Application | T1190 | Repurposed victims actively exploit other exposed AI servers to expand the botnet |

---

## 3. Malware & Tools

| Name | Type | Description |
|------|------|-------------|
| **PoeLLM** (`libgcrypt`) | ELF cryptominer / botnet agent | Main payload; ELF binary distributed under the `libgcrypt` name; includes remote shell, XMRig/Iron miners, HTTP scanning, and exploit deployment capabilities |
| **XMRig** | Cryptominer | Open-source Monero miner; deployed by PoeLLM for resource hijacking |
| **Iron miner** | Cryptominer | Secondary cryptocurrency miner deployed alongside XMRig |
| **Kryptex** | Mining pool service | Russian cryptocurrency-mining pool used as the mining endpoint; legitimate service abused for mining output routing |

---

## 4. Threat Actor / Campaign Attribution

| Field | Value |
|-------|-------|
| Campaign Name | Canto Incognito (Black Lotus Labs designation) |
| Malware | PoeLLM |
| Motivation | Financial — cryptocurrency mining |
| Attribution Confidence | Moderate |
| Attribution Basis | In-malware Italian-language comments; infrastructure patterns |
| Suspected Origin | Italy (assessed with moderate confidence by Black Lotus Labs) |
| Activity Start | April 13, 2026 (first GitHub poem commit) |
| Scale | 3,400+ victim servers; peak 800+ active daily |
| Primary Targets | Exposed LiteLLM, Ollama, Gotenberg, Gitea, and Ivanti Sentry servers |

---

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name IN ("xmrig","xmrig64","xmrig-notls","xmrig.exe","iron-miner")
     OR (Processes.process_name="libgcrypt" AND Processes.process!="*/usr/lib/*")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=100
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```
*Detects XMRig, Iron miner, or suspicious libgcrypt process execution — PoeLLM payload stage.*

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_ip IN ("92.119.164.50","103.249.201.108","178.128.14.204",
    "191.37.28.160","89.39.253.46","120.224.114.212","5.78.73.122","15.204.178.28",
    "92.119.165.74")
     OR All_Traffic.dest_port IN (3778)
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.process_name
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(dest,"92\.119\.164\.50|103\.249\.201\.108|178\.128\.14\.204"), 100,
    dest_port=3778, 85,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime src dest dest_port process_name risk_score
```
*Detects outbound connections to known PoeLLM C2 IPs or C2 port 3778.*

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_host="raw.githubusercontent.com"
    All_Traffic.process_name IN ("python3","python","node","litellm","ollama","gotenberg","gitea")
  by All_Traffic.src All_Traffic.dest_host All_Traffic.process_name All_Traffic.user
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=75
| where risk_score >= 75
| table firstTime lastTime src dest_host process_name user risk_score
```
*Detects AI service processes (LiteLLM, Ollama, Gotenberg, Gitea) fetching raw content from GitHub — consistent with PoeLLM's poem-based C2 resolution.*

---

## 6. Executive Summary

Lumen's Black Lotus Labs published the **Canto Incognito** research on October 7, 2026, documenting a financially motivated cryptomining campaign that compromised 3,400+ internet-exposed AI and developer servers. The campaign, named after the malware's novel C2 technique, deploys **PoeLLM** — an ELF binary distributed as `libgcrypt` — that hides its C2 server address inside a GitHub-hosted poem. The malware extracts specific words from the poem and maps them through a hard-coded dictionary to an IPv4 address, allowing the operator to rotate C2 infrastructure simply by editing the poem. Eleven poem updates were observed between April 13 and October 2026.

Primary targets are internet-exposed instances of **LiteLLM** (CVE-2026-42271), **Ollama**, **Gotenberg**, and **Gitea**, along with at least one **Ivanti Sentry** appliance (CVE-2026-10520). After compromise, victims are conscripted as botnet scanners targeting ports 3000/4000 and are used to deploy XMRig/Iron miners connected to the **Kryptex** mining pool. Attribution is moderate-confidence Italian based on in-malware comments and infrastructure patterns.

Security teams should immediately scan for XMRig/Iron miner processes on any server running AI services, audit outbound connections on ports 3778/5001/5002/9999, and patch LiteLLM to 1.83.7+ and Ivanti Sentry per vendor guidance.
