---
scraped_at: 2026-07-25T01:30:00Z
source_url: https://www.elastic.co/security-labs/telepuz-maas-malware-clickfix
report_type: threat-intel
severity: high
title: "TELEPUZ: Modular MaaS Delivered via ClickFix-VIDAR Chain with WebSocket C2 and Polygon Blockchain Fallback"
---

# TELEPUZ: Modular MaaS Delivered via ClickFix-VIDAR Chain with WebSocket C2 and Polygon Blockchain Fallback

**Source:** Elastic Security Labs  
**Published:** 2026-07-16  
**Severity:** High

## Summary

Elastic Security Labs published analysis of TELEPUZ, a modular Malware-as-a-Service framework delivered via a two-stage ClickFix-VIDAR chain. TELEPUZ distinguishes itself with three technically novel capabilities: real-time WebSocket C2 (WSS), a Chrome DevTools Protocol (CDP) / WebDriver BiDi web injector for browser session hijacking without requiring a browser extension, and a Polygon smart contract dead-drop for C2 URL rotation (EtherHiding technique).

TELEPUZ is sold as a MaaS platform with a modular plugin catalog including an info stealer, keylogger, web injector, screen recorder, and persistence manager. The ClickFix delivery chain first deploys VIDAR stealer to harvest credentials and report operational success to the TELEPUZ orchestration infrastructure, which then deploys the full TELEPUZ implant.

## Threat Actor

Unknown financially motivated operator; TELEPUZ sold as a MaaS service. Multiple affiliates observed running campaigns; primary targeting observed in North America and Western Europe financial sector, H1–Q3 2026.

## Attack Chain

### Stage 1: ClickFix → VIDAR Stealer
1. Target visits lure page (fake browser update, fake CAPTCHA verification, or malicious ad)
2. ClickFix payload instructs user to paste PowerShell command into Run dialog
3. PowerShell downloads and executes VIDAR stealer
4. VIDAR harvests: browser credentials, cookies, autofill data, cryptocurrency wallets, files matching configurable patterns
5. VIDAR reports success (stolen data + victim fingerprint) to TELEPUZ MaaS C2

### Stage 2: TELEPUZ Module Deployment
6. TELEPUZ MaaS operator reviews victim profile; pushes TELEPUZ core loader to victim
7. TELEPUZ core establishes WebSocket C2 (WSS://); heartbeat every 30s
8. Additional modules downloaded on demand from C2 or recovered from Polygon contract if primary C2 unavailable
9. Web injector module deployed: attaches to running Chrome instance via CDP/WebDriver BiDi to inject JavaScript into banking and financial site sessions

## Technical Details

### TELEPUZ Core
- Language: .NET (C#), obfuscated with custom string encryption
- C2: WebSocket (WSS://) over port 443 for bidirectional real-time control
- Blockchain fallback: Polygon smart contract stores encrypted C2 URLs; client calls `getConfig()` view function; technique identical to EtherHiding but on Polygon (lower gas cost) instead of BSC
- Plugin loading: AES-encrypted PE modules loaded reflectively; modules identified by 4-byte plugin ID

### Web Injector Module (CDP/WebDriver BiDi)
- Attaches to running Chrome/Edge browser instances using Chrome DevTools Protocol (CDP) remote debugging interface
- Does NOT require a browser extension or browser restart — exploits CDP's legitimate remote automation interface
- Injects JavaScript into page context of targeted banking/financial domains using `Runtime.evaluate` CDP method
- Capabilities: form field interception (credentials, OTP), cookie theft, screenshot of active tab, DOM manipulation for web fraud (e.g., altering transfer amounts shown to user while submitting different values)
- Also supports WebDriver BiDi (bidirectional WebDriver protocol) as an alternative attachment method on newer Chrome versions

### Persistence
- Scheduled task created via `schtasks.exe /create /tn "Microsoft Edge Update" /tr <loader_path> /sc onlogon`
- Alternatively: registry Run key in `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|----|
| Execution | User Execution (ClickFix) | T1204.002 |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 |
| Persistence | Scheduled Task/Job: Scheduled Task | T1053.005 |
| Persistence | Boot or Logon Autostart: Registry Run Keys | T1547.001 |
| Collection | Browser Session Hijacking | T1185 |
| Collection | Credentials from Password Stores: Credentials from Web Browsers | T1555.003 |
| Collection | Input Capture: Keylogging | T1056.001 |
| C2 | Application Layer Protocol: Web Protocols (WebSocket) | T1071.001 |
| C2 | Dynamic Resolution (Blockchain dead-drop) | T1568 |

## Lockheed Martin Kill Chain

Exploitation (ClickFix) → Installation → C2 → Actions on Objectives

## Detections

- `detections/execution/clickfix_user_execution_lure.md` — covers ClickFix delivery stage
- `detections/command_and_control/smartloader_polygon_blockchain_c2.md` — covers Polygon EtherHiding C2 fallback pattern
- `detections/collection/telepuz_cdp_browser_session_hijacking.md` — NEW detection for CDP-based web injector

## References

- [Elastic Security Labs — TELEPUZ: MaaS Malware via ClickFix (2026-07-16)](https://www.elastic.co/security-labs/telepuz-maas-malware-clickfix)
- [MITRE ATT&CK — T1185 Browser Session Hijacking](https://attack.mitre.org/techniques/T1185/)
- [MITRE ATT&CK — T1568 Dynamic Resolution](https://attack.mitre.org/techniques/T1568/)
- [Chrome DevTools Protocol documentation](https://chromedevtools.github.io/devtools-protocol/)
- [EtherHiding technique — Guardio Labs research](https://labs.guard.io/etherhiding-hiding-web2-malicious-code-in-web3-smart-contracts-65ea78efad16)
- [MITRE ATT&CK — T1204.002 User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
