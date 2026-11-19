# COLD RELIC MFA Fatigue Followed by Rogue Device / Passkey Registration

## Description

Detects Russia FSB actor COLD RELIC's (COLDRIVER / Star Blizzard / Callisto) core Google Workspace persistence chain: a burst of MFA push failures indicating deliberate push fatigue, followed by a successful login and near-immediate enrollment of a new MFA device, passkey, or backup code by the same user/IP.

This technique is used because rogue device and passkey enrollment creates persistence that survives subsequent password resets — a distinguishing characteristic of COLD RELIC intrusions. The attacker registers the new device within minutes of the fatigue success to establish a durable foothold before the victim reacts.

Google Workspace equivalents (Device Registered, Passkey Enrolled) are the target events. The detection joins two data streams: login challenge/failure events and device enrollment events within a 1-hour window of the successful post-fatigue login.

**False positives:** Legitimate users who genuinely accepted a push (after a battery of accidental approvals) and then enrolled a new device immediately after. Analyst should verify: Was the enrolling device/location expected? Did the IP change between failures and success? Was the IP a residential proxy network? Were Alert Center notifications deleted shortly after?

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Credential Access |
| Tactic ID | TA0006 |
| Technique | Multi-Factor Authentication Request Generation |
| Technique ID | T1621 |
| Secondary Tactic | Persistence |
| Secondary Tactic ID | TA0003 |
| Secondary Technique | Account Manipulation: Device Registration |
| Secondary Technique ID | T1098.005 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Actions on Objectives |

## Splunk Detection Query

```spl
`google_workspace` log_type=login
| eval event_name=coalesce(events{}.name, name)
| eval user=coalesce(actor.email, actor_email, user)
| eval ip=coalesce(ipAddress, ip_address)
| eval login_challenge_method=coalesce(login_challenge_method, parameters{}.value)
| eval is_failure=if(event_name="login_failure" AND login_challenge_method IN ("push", "phone", "totp", "passkey"), 1, 0)
| eval is_success=if(event_name="login_success", 1, 0)
| bin _time span=30m
| stats
    sum(is_failure) as mfa_failures,
    sum(is_success) as login_successes,
    max(_time) as success_time
  by user ip _time
| where mfa_failures >= 5 AND login_successes >= 1
| join type=inner user [
    search `google_workspace` log_type=login OR log_type=device
    | eval event_name=coalesce(events{}.name, name)
    | eval user=coalesce(actor.email, actor_email, user)
    | search event_name IN ("DEVICE_REGISTER_COMPLETE", "2sv_enroll", "PASSKEY_ENROLLED", "BACKUP_CODE_GENERATED")
    | stats count as enroll_count min(_time) as enroll_time by user
]
| where enroll_count >= 1 AND enroll_time >= success_time AND enroll_time <= success_time + 3600
| eval risk_score=case(
    mfa_failures >= 15, 95,
    mfa_failures >= 10, 90,
    mfa_failures >= 5,  80,
    1=1, 70)
| where risk_score >= 80
| `security_content_ctime(success_time)`
| `security_content_ctime(enroll_time)`
| table success_time enroll_time user ip mfa_failures login_successes enroll_count risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| 15+ MFA failures before success → enrollment within 1 hour | 95 | Extreme push fatigue volume; near-certain adversary persistence attempt |
| 10–14 MFA failures before success → enrollment within 1 hour | 90 | High-volume fatigue; strong indicator of intentional compromise |
| 5–9 MFA failures before success → enrollment within 1 hour | 80 | Moderate fatigue pattern followed by suspicious enrollment; warrants immediate investigation |

Analyst triage questions:
- Was the IP a residential proxy or VPN? (COLD RELIC uses residential proxies geolocated near victims)
- Did Alert Center notifications get deleted within 1 hour of enrollment?
- Did a Customer Takeout (`CUSTOMER_TAKEOUT_INITIATED`) occur within 24 hours?
- Was the enrolled device type new for this user?
- Were OAuth broad mail scopes (`https://mail.google.com/`) granted shortly after?

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| COLD RELIC (COLDRIVER / Star Blizzard / Callisto / Gossamer Bear / UNC4057) | [MITRE ATT&CK — G1091 COLDRIVER](https://attack.mitre.org/groups/G1091/), [GTIG — COLD RELIC Case Study (Nov 17, 2026)](https://cloud.google.com/blog/topics/threat-intelligence/cold-relic-a-case-study-in-impersonation-and-compromise) |

## References

- [GTIG — COLD RELIC: A Case Study in Impersonation and Compromise (2026-11-17)](https://cloud.google.com/blog/topics/threat-intelligence/cold-relic-a-case-study-in-impersonation-and-compromise)
- [MITRE ATT&CK — T1621: MFA Request Generation](https://attack.mitre.org/techniques/T1621/)
- [MITRE ATT&CK — T1098.005: Account Manipulation: Device Registration](https://attack.mitre.org/techniques/T1098/005/)
- [MITRE ATT&CK — G1091: COLDRIVER](https://attack.mitre.org/groups/G1091/)
- [Threat-intel report: COLD RELIC Google Workspace](../../threat-intel/2026-11-17_cloud-google-com-gtig-cold-relic-workspace-compromise.md)
