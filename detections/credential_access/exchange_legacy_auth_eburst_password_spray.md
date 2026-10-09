# Exchange Legacy Auth Password Spray (EBurst-Style)

## Description

Detects automated password-spraying attacks against Microsoft Exchange on-premises and Exchange Online using legacy authentication protocols (OWA, EWS, IMAP, MAPI over HTTP, ActiveSync). This pattern is the hallmark of tools such as EBurst — the open-source Exchange sprayer documented in joint advisory AA26-281A (October 8, 2026) used by the Flax Typhoon / Integrity Technology Group campaign.

Legacy authentication endpoints accept Basic Auth and NTLM without device compliance checks, making them the preferred target for bulk credential spraying. The detection identifies the password spray pattern — many distinct usernames attempted from a single source IP — and also covers volume-based brute force (single user, many attempts).

**Expected false positives:** Legitimate security testing (Atomic Red Team, internal red teams), mail client misconfiguration causing repeated re-auth, or MFA roll-out scenarios that create short-lived spikes in EWS failure events from mobile device sync. Tune the `distinct_users` and `total_failures` thresholds to the environment's baseline authentication volumes.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Credential Access |
| Tactic ID | TA0006 |
| Technique | Brute Force: Password Spraying |
| Technique ID | T1110.003 |

Secondary:

| Tactic | Technique ID | Technique |
|--------|-------------|-----------|
| Credential Access | T1110.001 | Brute Force: Password Guessing |
| Initial Access | T1078.004 | Valid Accounts: Cloud Accounts |
| Collection | T1114.002 | Email Collection: Remote Email Collection |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Actions on Objectives |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Authentication
  where Authentication.action="failure"
    AND Authentication.app IN (
      "OWA","Exchange Web Services","Exchange ActiveSync",
      "Microsoft Exchange","Office365","IMAP","MAPI over HTTP"
    )
  by Authentication.src Authentication.dest Authentication.user
| `drop_dm_object_name(Authentication)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| stats dc(user) as distinct_users
        count as total_failures
        values(user) as users_attempted
        min(firstTime) as firstTime max(lastTime) as lastTime
    by src dest
| eval spray_window_minutes=round((strptime(lastTime,"%Y-%m-%dT%H:%M:%S")-strptime(firstTime,"%Y-%m-%dT%H:%M:%S"))/60,1)
| eval risk_score=case(
    distinct_users >= 50 AND spray_window_minutes <= 30, 95,
    distinct_users >= 20 AND spray_window_minutes <= 60, 85,
    distinct_users >= 10 AND spray_window_minutes <= 120, 75,
    total_failures >= 100 AND distinct_users = 1, 70,
    1=1, 50)
| where risk_score >= 75
| table firstTime lastTime src dest distinct_users total_failures spray_window_minutes users_attempted risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| ≥50 distinct users in ≤30 min from same IP | 95 | Automated high-speed spray; near-certain malicious |
| ≥20 distinct users in ≤60 min from same IP | 85 | Likely EBurst or similar Exchange sprayer; high confidence |
| ≥10 distinct users in ≤120 min from same IP | 75 | Moderate spray rate; suspicious, investigate |
| ≥100 failures against a single user | 70 | Targeted brute force against known account |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Flax Typhoon / Integrity Technology Group | [CISA AA26-281A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-281a) · [MITRE G1044](https://attack.mitre.org/groups/G1044/) |
| Flax Typhoon (Ethereal Panda, Red Juliett) | [Microsoft Threat Intel — Flax Typhoon](https://www.microsoft.com/en-us/security/blog/2023/08/24/flax-typhoon-using-legitimate-software-to-quietly-access-taiwanese-organizations/) |
| FortiBleed operators (ransomware affiliates) | [FBI/Secret Service Joint Advisory Oct 2026](https://www.ic3.gov) |
| Star Blizzard / SEABORGIUM | [MITRE G1033](https://attack.mitre.org/groups/G1033/) |

## References

- [CISA/FBI/NSA/NCSC-UK Joint Advisory AA26-281A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-281a)
- [EBurst — open-source Exchange password sprayer](https://github.com/dafthack/MailSniper) (comparable tool for reference; EBurst is the tool named in the advisory)
- [MITRE T1110.003 — Brute Force: Password Spraying](https://attack.mitre.org/techniques/T1110/003/)
- [MITRE T1114.002 — Email Collection: Remote Email Collection](https://attack.mitre.org/techniques/T1114/002/)
- [Microsoft: Detecting and preventing legacy authentication](https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/block-legacy-authentication)
