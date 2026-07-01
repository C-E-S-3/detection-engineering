---
scraped_at: 2026-07-01T00:00:00Z
source_url: https://www.huntress.com/blog/lshiy-password-spray-attack
report_type: threat-intel
severity: high
title: LSHIY Azure CLI ROPC Password Spray — 81M+ Attempts, 78 Accounts Compromised Across 64 Orgs via Conditional Access Bypass
---

## 1. IOCs

### Network Infrastructure (Threat Actor — LSHIY LLC)
| Indicator | Type | Context |
|-----------|------|---------|
| `2a0a:d683::/32` | IPv6 CIDR | LSHIY LLC (AS32167) — primary spray infrastructure; the overwhelming majority of 81M+ login attempts sourced from this block |
| AS32167 | ASN | LSHIY LLC — registered June 14, 2021; IPv6 range associated with China-origin despite US registration |
| AS955 | ASN | LSHIY LLC — secondary ASN registered June 22, 2022; some IP addresses resolve to China |

### Azure Authentication Artifacts
| Artifact | Value | Context |
|----------|-------|---------|
| Application (ClientId) | `04b07795-8ddb-461a-bbee-02f9e1bf7b46` | Azure CLI application ID — used by LSHIY to authenticate via ROPC flow; this is a legitimate but abused Azure application |
| Token endpoint | `login.microsoftonline.com/{tenant}/oauth2/v2.0/token` | ROPC grant_type `password` submitted directly, bypassing CAP MFA enforcement |
| Log field indicator | `authProtocol=ROPC` or `clientAppUsed=Azure CLI` | Present in Microsoft Entra sign-in logs when ROPC flow is used |

### File Hashes
None published.

### Domains
None (attack targets Microsoft-owned login infrastructure; no attacker domains required).

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Procedure |
|--------|-------------|----------------|-----------|
| Credential Access | T1110.003 | Brute Force: Password Spraying | 81M+ ROPC authentication attempts targeting Azure CLI across 64+ organizations June 12–26, 2026 |
| Credential Access | T1110.001 | Brute Force: Password Guessing | Credential spray using previously breached username/password combinations from combo lists; targets accounts that never rotated exposed passwords |
| Defense Evasion | T1550.001 | Use Alternate Authentication Material: Application Access Token | ROPC OAuth flow (`grant_type=password`) bypasses Conditional Access Policies that enforce MFA for interactive sign-ins; CAP does not apply to legacy/ROPC flows unless explicitly configured |
| Initial Access | T1078 | Valid Accounts | After ROPC authentication succeeds, attacker obtains full Azure CLI access token scoped to Microsoft Graph |
| Defense Evasion | T1562.001 | Impair Defenses: Disable or Modify Tools | MFA bypass is achieved by exploiting CAP configuration gap — not disabling MFA but targeting a flow the MFA policy does not cover |

**Key Technical Detail — ROPC CAP Gap:**
Most organizations configure Conditional Access Policies to require MFA for browser and modern auth flows. ROPC (`grant_type=password`) is a deprecated OAuth 2.0 flow that submits username+password directly to the token endpoint. Unless the CAP policy explicitly blocks legacy authentication or includes an Azure CLI exclusion with MFA enforcement, ROPC authenticates with only credentials — even if MFA is "enabled" for the account.

**Attack Timeline:**
- June 12, 2026: Campaign begins — 2–4 accounts compromised per day
- June 12–21, 2026: Steady cadence, averaging 2–4 compromised accounts/day
- June 19, 2026: Spike — 12 user accounts compromised in a single day
- June 22, 2026: Major escalation — 30 identities across 23 businesses compromised
- June 26, 2026: Last observed activity in Huntress's telemetry

---

## 3. Malware & Tools

No custom malware identified. Attack uses the native Azure CLI tooling and the ROPC OAuth 2.0 flow — both are legitimate capabilities abused for credential spray. The attacker's infrastructure appears to be a high-volume automated spraying platform (no specific tooling name identified).

---

## 4. Threat Actor / Campaign Attribution

| Field | Detail |
|-------|--------|
| Tracked as | LSHIY LLC (internet infrastructure provider / spray operator) |
| Attribution | Unknown criminal actor; no nation-state attribution in available reporting |
| Infrastructure | LSHIY LLC (AS32167, AS955) — registered in US but IPv6 ranges originate from China |
| Target selection | Opportunistic; solely based on password prevalence in breached combo lists; no specific business type, industry, or geography targeted |
| Credential source | Previously breached username/password pairs not rotated by victims |

**Secondary context from Huntress:** Credential spray attacks across all tracked flows surged by over **155×** across Huntress's customer base during this campaign period, indicating LSHIY ROPC spray is one component of a broader credential market/spray operation.

---

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Authentication
  where Authentication.app="Azure CLI"
    Authentication.authentication_method IN ("Password","ROPC","resourceOwnerPasswordCredential")
  by Authentication.src Authentication.user Authentication.app Authentication.authentication_method Authentication.action
| `drop_dm_object_name(Authentication)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    action="failure" AND count > 10, 75,
    action="success", 90,
    1=1, 50)
| where risk_score >= 50
| table firstTime lastTime src user app authentication_method action count risk_score
```

```spl
`azure_ad`
| where category="SignInLogs"
| search AppId="04b07795-8ddb-461a-bbee-02f9e1bf7b46"
    (AuthenticationProtocol="ropc" OR AuthenticationProtocol="resourceOwnerPasswordCredential"
     OR clientAppUsed="Azure CLI" OR legacyTlsClientAuthenticationEnabled=true)
| stats count dc(UserPrincipalName) as unique_accounts dc(IPAddress) as src_ips
    min(_time) as firstTime max(_time) as lastTime
    values(UserPrincipalName) as users values(IPAddress) as srcs
    by AppId AppDisplayName
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    count > 1000 AND unique_accounts > 5, 90,
    count > 100, 75,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime AppDisplayName unique_accounts count src_ips users srcs risk_score
```

```spl
`azure_ad`
| where category="SignInLogs"
| search IPAddress="2a0a:d683:*" OR CIDR_match(IPAddress,"2a0a:d683::/32")
| stats count dc(UserPrincipalName) as targets
    min(_time) as firstTime max(_time) as lastTime
    values(UserPrincipalName) as users
    by IPAddress AppDisplayName ResultType
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime IPAddress AppDisplayName ResultType targets count users risk_score
```

---

## 6. Executive Summary

Between June 12 and 26, 2026, a threat actor operating from LSHIY LLC infrastructure (IPv6 range `2a0a:d683::/32`, AS32167) executed a large-scale automated credential spray against Microsoft Azure using the **Resource Owner Password Credentials (ROPC)** legacy OAuth 2.0 flow targeting the Azure CLI application (`04b07795-8ddb-461a-bbee-02f9e1bf7b46`).

The campaign executed **81+ million** authentication attempts and successfully compromised **78 Microsoft accounts** across **64 organizations**. The critical enabler was a Conditional Access Policy (CAP) configuration gap: while most organizations had MFA enforced via CAP for modern browser flows, the ROPC flow — where credentials are submitted directly to the token endpoint — was not explicitly covered by their MFA policies, allowing successful authentication with credentials alone.

Huntress reported credential spray attacks overall surged 155× across their customer base. The attacker's credential source was previously breached username/password pairs from combo lists targeting accounts whose passwords had never been rotated.

**Remediation:**
1. Create a Conditional Access Policy that **blocks legacy authentication** (Grant: Block) — Microsoft Entra provides a dedicated "Legacy Authentication" client apps filter
2. Alternatively, require MFA explicitly for Azure CLI via a CAP targeting the Azure CLI app ID
3. Enable **Microsoft Entra Password Protection** to detect and alert on ROPC attempts
4. Search Entra sign-in logs for `clientAppUsed=Azure CLI` combined with `authProtocol=ROPC` to identify any existing compromise

**Severity: High** — Active ongoing campaign with confirmed organizational compromises; ROPC bypass of CAP is a systemic configuration weakness affecting any Azure tenant that has not explicitly blocked legacy auth.
