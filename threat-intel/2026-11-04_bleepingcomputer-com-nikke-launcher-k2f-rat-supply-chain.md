# NIKKE PC Game Launcher Supply Chain Attack Distributing K2F RAT

**Date Added:** 2026-11-04
**Source:** BleepingComputer / WormW GitHub Analysis (nikke_malware_analysis)
**Severity:** High
**Status:** Active

---

## Summary

Threat actors compromised the NIKKE: Goddess of Victory PC game launcher CDN to serve poisoned JavaScript
assets, delivering the K2F remote access trojan to players who launched the game between approximately
October 28 and November 3, 2026. The attack used a novel LuaJIT 2.0 bytecode payload distributed as a
browser-extension-style bundle, side-loaded via a legitimate Chrome component DLL path. The RAT exfiltrates
credentials, screenshots, and data from 1,790 targeted paths — including SSH keys, cloud provider
credentials, and 28 cryptocurrency wallet browser extensions — via Slack webhook channels under attacker
control.

---

## Threat Actor

**Name:** K2F Operator (unattributed)
**Type:** Financially motivated cybercrime (crypto/credential theft focus)
**Attribution confidence:** Low — actor name derived from internal RAT artifacts (`k2f_chan` named pipe,
TLS certificate `CN=k2f operator CA`, staging path `%TEMP%\k2f-bcreds-*`)
**Prior activity:** No confirmed prior campaigns

---

## Attack Chain

1. **Supply chain compromise:** Attacker modifies two CDN-hosted JavaScript assets served by the NIKKE
   launcher update mechanism:
   - `FeedList.feb647c9.js` (SHA256: `f3e93d049851d5c19552c7d9b73c8be4580dc9d549e8f65f9f0c357c1df9d252`)
   - `vue-bucket.min.js` (SHA256: `3aaafbd612f04501a6fdb0bb8b2f8a87796223e5584ac18ea5eb180feeafb193`)

2. **Dropper execution:** The poisoned JS writes and executes a loader DLL (`Sample-A.dll`) into the Chrome
   component path (`%LOCALAPPDATA%\Google\Chrome\Application\<version>\`), which is trusted by the host.
   - Sample-A.dll SHA256: `f3e93d049851d5c19552c7d9b73c8be4580dc9d549e8f65f9f0c357c1df9d252`

3. **Payload delivery:** The loader DLL fetches the K2F LuaJIT bytecode payload (`Sample-B.bundle`) from
   `analytics[.]insightjs[.]com`.
   - Sample-B.bundle SHA256: `cc0ad05bfe85940a6067b3a72c182d3953339129206634141926d5d0b35973ec`

4. **C2 establishment:** K2F establishes a named pipe (`\\.\pipe\k2f_chan`) and connects to its C2 server
   over TLS using a self-signed certificate with `CN=k2f operator CA`. C2 IP: `89[.]127[.]233[.]127`.

5. **Data collection and exfiltration:** K2F implements a 19-command protocol covering:
   - Credential harvesting from browsers, SSH keys, cloud CLI configs (AWS, GCP, Azure)
   - Screenshot capture → `%TEMP%\k2f_screen_*.jpg`
   - Credential staging → `%TEMP%\k2f-bcreds-*`
   - 28 crypto wallet browser extension targets
   - 1,790 total targeted file paths
   - Exfiltration via Slack webhook API (T1567.002)

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|----|-------------|
| Supply Chain Compromise: Compromise Software Supply Chain | T1195.002 | Poisoned CDN assets in game launcher update |
| DLL Side-Loading | T1574.002 | Loader DLL placed in Chrome component directory |
| Credentials from Password Stores | T1555 | Browser credential harvesting |
| Screen Capture | T1113 | Screenshots staged to `%TEMP%\k2f_screen_*.jpg` |
| Exfiltration Over Web Service | T1567.002 | Data exfiltrated via Slack webhooks |
| Command and Scripting Interpreter | T1059 | LuaJIT bytecode payload execution |
| Ingress Tool Transfer | T1105 | Payload fetched from analytics[.]insightjs[.]com |
| Data from Local System | T1005 | 1,790 targeted file paths including crypto wallets |
| Encrypted Channel | T1573.002 | TLS with self-signed `CN=k2f operator CA` certificate |

**Primary Tactic:** Command and Control (TA0011)
**Secondary Tactics:** Initial Access (TA0001), Defense Evasion (TA0005), Credential Access (TA0006),
Collection (TA0009), Exfiltration (TA0010)

---

## Kill Chain Phase

**Delivery** → **Exploitation** → **Installation** → **C2** → **Actions on Objectives**

---

## Indicators of Compromise

### Domains

| Indicator | Context |
|-----------|---------|
| `analytics[.]insightjs[.]com` | K2F RAT C2 — payload delivery and beacon |
| `insightjs[.]com` | K2F RAT operator infrastructure |
| `insightjs[.]org` | K2F RAT operator infrastructure (alternate) |

### IP Addresses

| Indicator | Context |
|-----------|---------|
| `89[.]127[.]233[.]127` | K2F RAT primary C2 server |
| `89[.]126[.]250[.]172` | K2F RAT secondary / staging server |

### File Hashes (SHA256)

| Hash | Description |
|------|-------------|
| `f3e93d049851d5c19552c7d9b73c8be4580dc9d549e8f65f9f0c357c1df9d252` | Sample-A.dll — K2F loader DLL, side-loads via Chrome component path |
| `cc0ad05bfe85940a6067b3a72c182d3953339129206634141926d5d0b35973ec` | Sample-B.bundle — K2F LuaJIT 2.0 bytecode payload (19-command C2 protocol) |
| `2f2aac505f486067af6831d6c75ea74df63acb1ed4e4002709c5962c68bd9203` | FeedList.feb647c9.js — poisoned CDN asset (original game launcher JS) |
| `3aaafbd612f04501a6fdb0bb8b2f8a87796223e5584ac18ea5eb180feeafb193` | vue-bucket.min.js — poisoned CDN asset |

### Behavioral / Host Indicators

| Indicator | Type |
|-----------|------|
| `\\.\pipe\k2f_chan` | Named pipe created by K2F RAT |
| `CN=k2f operator CA` | TLS certificate CN used in C2 traffic |
| `%TEMP%\k2f-bcreds-*` | Credential staging path pattern |
| `%TEMP%\k2f_screen_*.jpg` | Screenshot staging path pattern |
| DLL written to `%LOCALAPPDATA%\Google\Chrome\Application\<ver>\` by non-Chrome process | Side-loading indicator |

---

## Detection Opportunities

1. **DNS/network:** Block and alert on `insightjs.com`, `analytics.insightjs.com`, `insightjs.org`
2. **Endpoint:** Alert on DLL writes to Chrome component path by non-Google-signed processes
3. **Endpoint:** Named pipe creation matching `k2f_chan`
4. **Network:** TLS certificate with CN containing `k2f operator`
5. **Endpoint:** File creation matching `%TEMP%\k2f-bcreds-*` or `%TEMP%\k2f_screen_*.jpg`
6. **Network:** Outbound HTTPS to `slack.com/api/chat.postMessage` from non-browser processes (exfil via Slack)

See: `detections/command_and_control/k2f_rat_insightjs_c2_dns.md`

---

## References

- [BleepingComputer — NIKKE PC game launcher hacked to spread remote access, data-stealing malware](https://www.bleepingcomputer.com/news/security/nikke-pc-game-launcher-hacked-to-spread-remote-access-data-stealing-malware/)
- [WormW / nikke_malware_analysis GitHub](https://github.com/WormW/nikke_malware_analysis/blob/main/README.en.md)
- [MITRE ATT&CK — T1195.002: Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/002/)
- [MITRE ATT&CK — T1574.002: DLL Side-Loading](https://attack.mitre.org/techniques/T1574/002/)
