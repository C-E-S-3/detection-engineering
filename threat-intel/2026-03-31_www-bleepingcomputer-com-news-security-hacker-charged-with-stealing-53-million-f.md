---
scraped_at: "2026-03-31T05:15:45-04:00"
source_url: "https://www.bleepingcomputer.com/news/security/hacker-charged-with-stealing-53-million-from-uranium-crypto-exchange/"
report_type: threat-intel
---

## 1. Indicators of Compromise (IOCs)

### IP Addresses
- None identified.

### Domains/URLs
- None identified.

### File Hashes
- None identified.

### Email Addresses
- None identified.

### File Names/Paths
- None identified.

### Registry Keys
- None identified.

### Mutex Names
- None identified.

### C2 Infrastructure
- None identified.

## 2. TTPs (MITRE ATT&CK Mapping)

### Tactics and Techniques
- **Tactic: Initial Access**
  - **Technique ID:** T1190 (Exploit Public-Facing Application)
    - **Description:** The attacker exploited vulnerabilities in Uranium Finance's smart contract code to gain unauthorized access and manipulate the system.

- **Tactic: Impact**
  - **Technique ID:** T1485 (Data Destruction)
    - **Description:** The attacker drained liquidity pools, effectively destroying the financial stability of the cryptocurrency exchange.

- **Tactic: Defense Evasion**
  - **Technique ID:** T1537 (Transfer Data to Cloud Account)
    - **Description:** The attacker laundered stolen cryptocurrency through Tornado Cash, a cryptocurrency mixer, to obscure the origin of funds.

## 3. Malware & Tools

- **Tools Used:**
  - Tornado Cash cryptocurrency mixer: Used to launder stolen funds and obscure the transaction trail.

## 4. Threat Actor / Campaign Attribution

- **Threat Actor:**
  - Name: Jonathan Spalletta (aliases: "Cthulhon", "Jspalletta")
  - Motivation: Financial gain
  - Target: Uranium Finance cryptocurrency exchange

- **Campaign Details:**
  - The attacker exploited vulnerabilities in Uranium Finance's smart contracts in two separate attacks in April 2021, stealing a total of $53.3 million worth of cryptocurrency.
  - The attacker laundered the stolen funds through Tornado Cash and spent the proceeds on luxury items and collectibles.

## 5. Splunk Detection Searches

### Detecting Exploitation of Public-Facing Applications (T1190)
```spl
index=web proxy
| search "AmountWithBonus" OR "transaction-verification logic"
| stats count by src_ip, http_user_agent, uri_path
| table src_ip, http_user_agent, uri_path, count
```
*This search identifies potential exploitation attempts by looking for references to the exploited variables in web traffic logs.*

### Detecting Cryptocurrency Mixer Usage (T1537)
```spl
index=crypto_logs
| search "Tornado Cash"
| stats count by src_ip, dest_ip, transaction_id
| table src_ip, dest_ip, transaction_id, count
```
*This search identifies transactions involving the Tornado Cash cryptocurrency mixer.*

### Monitoring Large Cryptocurrency Transfers (T1485)
```spl
index=crypto_logs
| where amount > 1000000
| stats count by src_ip, dest_ip, transaction_id, amount
| table src_ip, dest_ip, transaction_id, amount
```
*This search identifies unusually large cryptocurrency transactions that may indicate illicit activity.*

## 6. Executive Summary

A Maryland-based threat actor, Jonathan Spalletta (aliases: "Cthulhon", "Jspalletta"), has been charged with stealing $53.3 million from the Uranium Finance cryptocurrency exchange in April 2021. Spalletta exploited vulnerabilities in Uranium's smart contracts during two separate attacks, draining liquidity pools and forcing the exchange to shut down. The stolen funds were laundered through the Tornado Cash cryptocurrency mixer and used to purchase luxury items and collectibles. Organizations in the cryptocurrency sector are advised to review and secure their smart contract code, monitor for large or unusual transactions, and implement detection mechanisms for cryptocurrency mixer usage to mitigate similar threats.
