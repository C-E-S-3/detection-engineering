```markdown
---
scraped_at: 2026-03-27T06:40:17-04:00
source_url: https://www.bleepingcomputer.com/news/security/anti-piracy-coalition-takes-down-animeplay-app-with-5-million-users/
report_type: threat-intel
---

# Threat Intelligence Report: AnimePlay App Shutdown

## 1. Indicators of Compromise (IOCs)
### IP Addresses
- None identified.

### Domains and URLs
- AnimePlay app's 15 associated domains (specific domains not provided).
- Hosting servers for AnimePlay (specific URLs not provided).

### File Hashes
- None identified.

### Email Addresses
- None identified.

### File Names and Paths
- None identified.

### Registry Keys
- None identified.

### Mutex Names
- None identified.

### C2 Infrastructure Details
- Backend servers, associated databases, advertising tools, and 29 GitHub repositories containing full source code were surrendered to ACE.

## 2. TTPs (MITRE ATT&CK Mapping)
### Tactic: Impact
- **T1485 - Data Destruction**  
  ACE dismantled the AnimePlay operation by taking all infrastructure offline, including hosting servers, web domains, backend servers, and associated databases.

### Tactic: Impact
- **T1499 - Endpoint Denial of Service**  
  By taking control of the AnimePlay app and its infrastructure, ACE effectively restricted the operator's ability to rebuild or relaunch the service.

### Tactic: Initial Access
- **T1195 - Supply Chain Compromise**  
  ACE gained control of 29 GitHub repositories containing the full source code of the AnimePlay app, which could be used to analyze and prevent similar piracy operations.

## 3. Malware & Tools
### Malware Families/Names
- None identified.

### Legitimate Tools Abused
- GitHub repositories were used to host the source code for the AnimePlay app.

### Custom Tooling Descriptions
- AnimePlay app: A piracy-focused anime streaming platform hosting over 60 terabytes of anime TV shows and movies.

## 4. Threat Actor / Campaign Attribution
### Named Threat Groups
- Alliance for Creativity and Entertainment (ACE): A coalition backed by major television networks and film studios focused on dismantling illegal streaming services.

### Campaign Names
- AnimePlay Shutdown (March 2026)
- Photocall Shutdown (November 2025)

### Known Affiliations or Motivations
- ACE's primary motivation is to combat piracy and protect the creative economy through civil litigation, criminal referrals, and cease-and-desist operations.

### Targeted Sectors and Geographies
- Targeted Sector: Illegal streaming services, specifically anime and TV piracy platforms.
- Targeted Geography: Asia-Pacific region, with a focus on Indonesia for AnimePlay users.

## 5. Splunk Detection Searches
### Search for DNS queries to AnimePlay domains
```spl
index=dns sourcetype=dns
| search query IN ("animeplay-associated-domain1.com", "animeplay-associated-domain2.com", ...)
| stats count by query, src_ip
```
*Comment: Detects DNS queries to AnimePlay-associated domains.*

### Search for GitHub repository access related to AnimePlay
```spl
index=proxy sourcetype=access_combined
| search uri_path IN ("/AnimePlayRepo1", "/AnimePlayRepo2", ...)
| stats count by uri_path, src_ip
```
*Comment: Identifies access to GitHub repositories associated with AnimePlay.*

### Search for large data transfers indicative of AnimePlay hosting
```spl
index=network sourcetype=firewall
| search bytes_transferred > 100000000 AND dest_ip IN ("AnimePlay-hosting-IP1", "AnimePlay-hosting-IP2", ...)
| stats sum(bytes_transferred) by dest_ip, src_ip
```
*Comment: Flags large data transfers to hosting servers potentially linked to AnimePlay.*

## 6. Executive Summary
The Alliance for Creativity and Entertainment (ACE) has successfully dismantled the AnimePlay app, a major illegal anime streaming platform with over 5 million users, primarily in Indonesia. This operation involved taking control of the app's infrastructure, including hosting servers, web domains, and GitHub repositories containing its source code, effectively preventing the service from being relaunched. Organizations should monitor for any residual activity related to AnimePlay's infrastructure and implement measures to detect and block access to known piracy platforms. Collaboration with industry groups like ACE can help safeguard intellectual property and combat piracy effectively.
```
