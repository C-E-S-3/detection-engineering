---
scraped_at: "2026-11-27T00:00:00Z"
source_url: "https://socradar.io/weavelotus-redops-espionage-southeast-asia/"
report_type: threat-intel
severity: high
title: "WeaveLotus RedOps: GeoServer and osTicket Exploitation in Southeast Asian Government Espionage Campaign"
---

## 1. IOCs

### IP Addresses (Defanged)
| IP | Type | Description |
|----|------|-------------|
| 172.235.255[.]195 | Attacker infrastructure | Initial staging/tunneling VPS (Akamai/Linode); August–September 2026 |
| 172.235.245[.]49 | Attacker infrastructure | Replacement staging/tunneling VPS; observed from September 20, 2026 |
| 45.61.144[.]206 | Exfiltration server | MinIO object storage server used for data exfiltration staging |

### Exploited Vulnerabilities
| CVE | Product | Description | CVSS |
|-----|---------|-------------|------|
| CVE-2024-36401 | GeoServer (OGC) | Pre-auth Remote Code Execution via OGC evaluation of property name expressions; allows arbitrary code execution without authentication | Critical |
| CVE-2021-42235 | osTicket | SQL injection vulnerability | High |

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Tactic ID | Technique | Technique ID | Usage |
|--------|-----------|-----------|--------------|-------|
| Reconnaissance | TA0043 | Active Scanning: Vulnerability Scanning | T1595.002 | Reconnaissance against 30+ Indonesian government organizations; targeted scanning for GeoServer, osTicket, JasperReports |
| Initial Access | TA0001 | Exploit Public-Facing Application | T1190 | CVE-2024-36401 GeoServer exploitation; default JasperReports credentials; CVE-2021-42235 osTicket exploitation; Laravel debug mode exploitation |
| Execution | TA0002 | Command and Scripting Interpreter: Unix Shell | T1059.004 | Shell commands executed via GeoServer OGC eval injection |
| Persistence | TA0003 | Server Software Component: Web Shell | T1505.003 | Web shells deployed for persistent access |
| Discovery | TA0007 | File and Directory Discovery | T1083 | Enumeration of government document repositories |
| Collection | TA0009 | Data from Local System | T1005 | 31,418 files (~575 MB) exfiltrated from Thai military-affiliated organization; ~19 GB from Thai legislature; 349,782 policy records stolen |
| Collection | TA0009 | Archive Collected Data | T1560 | Archive creation (.tar, .tar.gz) for staging before exfiltration |
| Exfiltration | TA0010 | Exfiltration Over Web Service | T1567 | Data staged to MinIO exfiltration server (45.61.144.206) |
| Command and Control | TA0011 | Protocol Tunneling | T1572 | Tunneling infrastructure on staging VPS |
| Lateral Movement | TA0008 | Remote Services | T1021 | Lateral movement within compromised government networks |
| Credential Access | TA0006 | Credentials in Files | T1552.001 | Default JasperReports credentials and exposed config files |

---

## 3. Malware & Tools

| Name | Type | Description |
|------|------|-------------|
| MinIO | Legitimate tool abused | Self-hosted object storage service deployed by attackers for exfiltration staging |
| rsync / sshpass / curl | Legitimate utilities abused | Used for data transfer and exfiltration |

---

## 4. Threat Actor / Campaign Attribution

| Field | Detail |
|-------|--------|
| Threat Actor | WeaveLotus (also tracked as part of RedOps campaign) |
| Suspected Nexus | Vietnamese state sponsorship — moderate confidence |
| OceanLotus/APT32 Connection | Low confidence assessment; pending further corroboration |
| Campaign Name | RedOps |
| Activity Dates | August – September 2026 |
| Targets | 5 organizations in Thailand and Philippines (military, government, legislative institutions); 30+ Indonesian government organizations scanned, no confirmed breach |
| Objective | South China Sea intelligence collection; non-public government documents and credentials |
| Primary Source | SOCRadar Threat Research Unit (November 26, 2026) |

---

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest IN ("172.235.255.195", "172.235.245.49", "45.61.144.206")
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.action
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90, threat="WeaveLotus RedOps C2/Exfil Infrastructure"
| table firstTime lastTime src dest dest_port action threat risk_score
```

```spl
index=web OR index=proxy
(uri_path="*GetPropertyValue*" OR uri_path="*GetMap*" OR uri_path="*GetFeatureInfo*" OR uri_path="*wfs*" OR uri_path="*wms*")
(uri_query="*exec*" OR uri_query="*property*" OR uri_query="*exec(*)*)
  OR (uri_path="*geoserver*" AND status=200 AND bytes > 500)
| eval suspicious_params=if(match(uri_query, "exec\s*\(|Runtime\.getRuntime|ProcessBuilder|java\.lang"), "true", "false")
| where suspicious_params="true"
| stats count min(_time) as firstTime max(_time) as lastTime values(src_ip) as src_ips values(uri_path) as paths by host
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85, threat="CVE-2024-36401 GeoServer RCE Attempt"
| table firstTime lastTime host src_ips paths count risk_score threat
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN ("geoserver", "java", "tomcat")
     AND Processes.process_name IN ("bash", "sh", "curl", "wget", "python", "python3", "nc", "ncat", "perl")
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85, threat="GeoServer/Java Post-Exploitation Shell Spawn"
| table firstTime lastTime dest user parent_process_name process_name process risk_score threat
```

---

## 6. Executive Summary

SOCRadar's Threat Research Unit disclosed the WeaveLotus "RedOps" campaign on November 26, 2026. The campaign represents a systematic espionage operation targeting Southeast Asian government and military institutions, with a focus on intelligence relevant to South China Sea territorial disputes.

**Scope:** WeaveLotus compromised five organizations in Thailand and the Philippines during August–September 2026, including military-affiliated networks and a national legislature. Additionally, reconnaissance was conducted against 30+ Indonesian government organizations, though no confirmed breaches were found in Indonesia.

**Attack Chain:** The primary initial access vector was CVE-2024-36401, a critical pre-authentication RCE in GeoServer (a widely deployed open-source geospatial server common in government GIS infrastructure). The exploitation chain injects OGC property name expressions containing Java code that executes in the GeoServer process context. Secondary vectors included JasperReports servers with default credentials, an exposed osTicket installation (CVE-2021-42235), and a Laravel application running in debug mode.

**Data Stolen:** One Thai military-affiliated organization lost approximately 31,418 files (~575 MB). A Thai legislative body had approximately 19 GB stolen, including 349,782 policy records.

**Exfiltration:** Attackers deployed a MinIO self-hosted object storage server (45.61.144.206) as an intermediate exfiltration staging point, using native Unix utilities (rsync, sshpass, curl, tar/zst) for data transfer to avoid creating suspicious tooling footprints.

**Attribution:** SOCRadar attributes WeaveLotus to Vietnamese state-sponsored actors with moderate confidence, noting similarities to OceanLotus/APT32 (low confidence). The focus on South China Sea intelligence and the targeting pattern are consistent with Vietnamese national intelligence priorities.
