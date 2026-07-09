---
scraped_at: "2026-07-09T00:00:00Z"
source_url: "https://www.bleepingcomputer.com/news/security/pink-unc6671-rebrand-microsoft-365-passkey-aitm-phishing/"
report_type: threat-intel
severity: high
title: "Pink (UNC6671 Rebrand) AiTM Passkey Phishing Targets Microsoft 365 with BIP-39 Distraction and FOCI Token Theft"
---

## 1. IOCs

### Domains

| Domain | Context |
|--------|---------|
| `deploypasskey[.]com` | Pink phishing infrastructure; passkey enrollment lure page; AiTM proxy; reverse-proxies legitimate Entra ID sign-in |
| `passkeydeploy[.]com` | Pink phishing infrastructure; typosquat variant for IT automation and MDM lure personas |
| `assignpasskey[.]com` | Pink phishing infrastructure; HR onboarding passkey lure variant |
| `passkeyadd[.]com` | Pink phishing infrastructure; self-service passkey enrollment redirect; captures authentication tokens |

### IP Addresses

| IP | Context |
|----|---------|
| `185.178.208.153` | Pink phishing server; AiTM proxy backend; TLS certificate issued to one of the passkey domains |
| `172.93.100.252` | Pink phishing infrastructure; FOCI token exfiltration endpoint; hosts secondary phishing pages |
| `96.232.20.66` | Pink phishing infrastructure; ngrok-adjacent relay used for proxied Entra token capture |

### Behavioral Indicators

| Indicator | Context |
|-----------|---------|
| Entra ID sign-in from `ClientAppId = d3590ed6-52b3-4102-aeff-aad2292ab01c` | Microsoft Office application FOCI family; used in stolen-token replay to bypass per-app Conditional Access |
| Entra ID new device registration within minutes of first sign-in from new IP | Stolen token used immediately to register attacker-controlled device for persistent access |
| BIP-39 mnemonic wordlist submission during "passkey setup" flow | Novel distraction technique; victim shown fake seed phrase backup step while token exfiltration completes in background |
| Entra ID sign-in `authenticationRequirement = singleFactorAuthentication` when MFA expected | Indicates successful AiTM token theft; MFA was satisfied on the attacker-controlled proxy, not the legitimate device |

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|---------------|-------|
| Initial Access | T1566.002 | Phishing: Spearphishing Link | Passkey enrollment lure delivered via email or Teams message linking to deploypasskey[.]com |
| Initial Access | T1557.003 | Adversary-in-the-Middle: BITB | Browser-in-the-Browser iframe technique renders legitimate-looking Entra sign-in within attacker-controlled AiTM proxy |
| Credential Access | T1539 | Steal Web Session Cookie | AiTM proxy intercepts authenticated Entra session cookies and FOCI refresh tokens post-MFA |
| Credential Access | T1528 | Steal Application Access Token | FOCI refresh token for `d3590ed6-52b3-4102-aeff-aad2292ab01c` (Microsoft Office) reused across FOCI family apps |
| Persistence | T1098.005 | Account Manipulation: Device Registration | Attacker registers new device in Entra ID using stolen token within minutes of phishing; achieves compliant-device status |
| Defense Evasion | T1656 | Impersonation | Passkey-themed lure pages impersonate Microsoft IT communications and Okta enrollment portals |
| Defense Evasion | T1036 | Masquerading | FOCI token replayed using legitimate Microsoft Office client app ID to blend with normal Office 365 activity |

---

## 3. Malware & Tools

| Component | Type | Description |
|-----------|------|-------------|
| AiTM proxy (unnamed, custom) | Phishing infrastructure | Reverse-proxies Microsoft Entra ID sign-in pages in real time; captures session cookies and FOCI refresh tokens post-MFA completion |
| BIP-39 distraction module | Social engineering component | Novel technique introduced in Pink rebrand; presents victim with a fake "save your passkey recovery phrase" step (BIP-39 mnemonic wordlist UI) while token exfiltration completes server-side; increases dwell time on phishing page and reduces victim suspicion |

---

## 4. Threat Actor / Campaign Attribution

| Field | Value |
|-------|-------|
| Actor Name | Pink (rebrand of UNC6671 / BlackFile) |
| Attribution | Financially motivated; cybercriminal group; no nation-state link confirmed |
| Infrastructure Overlap | Previous UNC6671/BlackFile passkey domains tracked since May 2026 (`enrollms[.]com`, `passkeyms[.]com`, `setupsso[.]com`) |
| Campaign Start | July 2026 (Pink rebrand); original UNC6671 active since at least November 2025 |
| Targeting | Microsoft 365 organizations; focus on tenants with Entra ID Conditional Access and FIDO2/passkey rollout policies; IT administrators and help desk staff as initial targets |
| Novel Technique | BIP-39 mnemonic wordlist "backup" step introduced to extend victim time on phishing page while token capture completes |
| Key TTPs evolution | Moved from basic AiTM (BlackFile era) to FOCI family token abuse; ClientAppId `d3590ed6-52b3-4102-aeff-aad2292ab01c` allows token reuse across any app in the Microsoft Office FOCI family including OneDrive, SharePoint, Teams |

---

## 5. Splunk Detection Searches

```spl
`o365` Workload=AzureActiveDirectory Operation="UserLoggedIn"
  ClientAppId="d3590ed6-52b3-4102-aeff-aad2292ab01c"
  AuthenticationRequirement="singleFactorAuthentication"
| eval risk_score=80
| eval detection="Pink_FOCI_Token_Replay_Office_Client"
| table _time, UserId, ClientAppId, ClientIP, AuthenticationRequirement, risk_score, detection
```

```spl
`o365` Workload=AzureActiveDirectory Operation="Add registered owner to device"
  OR (Operation="UserLoggedIn" AND ResultStatus="Success")
| eval first_login=_time
| join type=inner UserId [
    search `o365` Workload=AzureActiveDirectory Operation="Add registered owner to device"
    | eval device_reg_time=_time
    | table UserId, device_reg_time
]
| eval time_delta=device_reg_time - first_login
| where time_delta < 300
| eval risk_score=90
| eval detection="Pink_AiTM_Rapid_Device_Registration"
| table _time, UserId, ClientIP, time_delta, risk_score, detection
```

```spl
`web` (dest_host IN ("deploypasskey.com","passkeydeploy.com","assignpasskey.com","passkeyadd.com")
  OR dest IN ("185.178.208.153","172.93.100.252","96.232.20.66"))
| eval risk_score=95
| eval detection="Pink_UNC6671_Phishing_Infrastructure"
| table _time, src_ip, dest, dest_host, uri, http_user_agent, risk_score, detection
```

```spl
`o365` Workload=AzureActiveDirectory Operation="UserLoggedIn"
  ResultStatus="Success"
  AuthenticationRequirement="singleFactorAuthentication"
| eval expected_mfa=if(match(UserType,"Member"), "multiFactor", "unknown")
| where expected_mfa="multiFactor" AND AuthenticationRequirement="singleFactorAuthentication"
| eval risk_score=75
| eval detection="AiTM_MFA_Downgrade_Indicator"
| table _time, UserId, ClientIP, AuthenticationRequirement, expected_mfa, risk_score, detection
```

---

## 6. Executive Summary

In July 2026, the cybercriminal group UNC6671 (previously tracked as BlackFile) rebranded to "Pink" and launched a new wave of adversary-in-the-middle phishing campaigns targeting Microsoft 365 tenants with Conditional Access policies and active passkey/FIDO2 rollouts. The rebrand introduces four new passkey-themed phishing domains (`deploypasskey[.]com`, `passkeydeploy[.]com`, `assignpasskey[.]com`, `passkeyadd[.]com`) backed by three new IP addresses.

The campaign exploits organizations performing passkey enrollment by impersonating IT communications about mandatory passkey setup. The AiTM proxy real-time reverse-proxies the Entra ID sign-in page, capturing authenticated session cookies and FOCI family refresh tokens after the victim completes MFA on the attacker-controlled proxy. A novel distraction technique — presenting the victim with a BIP-39 mnemonic seed phrase "backup step" — increases the time victims spend on the phishing page, allowing token exfiltration to complete undetected.

Stolen FOCI refresh tokens for `ClientAppId d3590ed6-52b3-4102-aeff-aad2292ab01c` (Microsoft Office) are immediately replayed to register an attacker-controlled device in Entra ID, achieving persistent access that survives password resets. The device appears compliant in most CA policy configurations.

**Immediate actions:** Block all four passkey-themed domains and three IPs at the proxy. Audit Entra ID for new device registrations occurring within five minutes of a first sign-in from a new IP. Implement Conditional Access policies requiring compliant or hybrid-joined devices, which partially mitigates FOCI token replay from unmanaged devices. Monitor for `AuthenticationRequirement=singleFactorAuthentication` on accounts expected to complete MFA.

---

## References

- [BleepingComputer — Pink (UNC6671 Rebrand) Microsoft 365 Passkey AiTM Phishing](https://www.bleepingcomputer.com/news/security/pink-unc6671-rebrand-microsoft-365-passkey-aitm-phishing/)
- [Okta ThreatIntel — Pink AiTM FOCI Token Theft Campaign](https://sec.okta.com/articles/2026/07/pink-unc6671-aitm-passkey-phishing)
- [Microsoft — FOCI and First Party App Token Policies](https://learn.microsoft.com/en-us/azure/active-directory/develop/family-of-client-apps)
- [MITRE ATT&CK T1557.003 — AiTM: BITB](https://attack.mitre.org/techniques/T1557/003/)
- [MITRE ATT&CK T1539 — Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539/)
- [MITRE ATT&CK T1098.005 — Account Manipulation: Device Registration](https://attack.mitre.org/techniques/T1098/005/)
- [MITRE ATT&CK T1528 — Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)
