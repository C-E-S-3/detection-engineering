# Kerberos Pre-Authentication Brute Force / Password Spray

## Description

A high volume of Kerberos pre-authentication failures (Event ID 4771) from a single source IP targeting multiple accounts within a short window is a strong indicator of password spraying or brute-force attacks. Event 4771 is generated when pre-authentication fails, typically due to an incorrect password (Status `0x18`) or account not found (Status `0x6`). This detection uses a 15-minute bin to capture rapid attack patterns.

False positive sources: Misconfigured applications with stale credentials, users with cached incorrect passwords on multiple devices, password reset operations. Tuning: adjust the `unique_accounts >= 5` and `total_failures >= 20` thresholds based on environment size and normal failure rates.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Credential Access |
| Tactic ID | TA0006 |
| Technique | Brute Force: Password Spraying |
| Technique ID | T1110.003 |
| Secondary Technique | Brute Force: Password Guessing (T1110.001) |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Actions on Objectives |

## Splunk Detection Query

```spl
`wineventlog_security` EventCode=4771
    (Status=0x18 OR Status=0x6)
| bin _time span=15m
| stats dc(Account_Name) as unique_accounts count as total_failures
    values(Account_Name) as targeted_accounts values(Status) as failure_codes
    by Client_Address _time
| eval has_bad_password=if(match(failure_codes, "0x18"), 1, 0)
| eval has_unknown_user=if(match(failure_codes, "0x6"), 1, 0)
| eval risk_score=case(
    unique_accounts >= 20 AND has_bad_password=1, 95,
    unique_accounts >= 10 AND has_bad_password=1, 90,
    unique_accounts >= 20 AND has_unknown_user=1, 85,
    unique_accounts >= 5 AND has_bad_password=1, 80,
    total_failures >= 50, 80,
    unique_accounts >= 5, 70,
    1=1, 60)
| where unique_accounts >= 5 OR total_failures >= 20
| sort - risk_score
| table _time Client_Address unique_accounts total_failures failure_codes targeted_accounts risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| 20+ accounts with bad password failures | 95 | Large-scale password spray - high confidence attack |
| 10+ accounts with bad password failures | 90 | Significant spray targeting many accounts |
| 20+ accounts with unknown user failures | 85 | Account enumeration via Kerberos |
| 5+ accounts with bad password failures | 80 | Moderate spray pattern |
| 50+ total failures from single IP | 80 | Brute force volume indicator |
| 5+ unique accounts targeted | 70 | Minimum spray threshold |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Any adversary performing password spraying | [MITRE ATT&CK - Password Spraying (T1110.003)](https://attack.mitre.org/techniques/T1110/003/) |
| Any adversary using kerbrute | [kerbrute - Kerberos brute-force tool](https://github.com/ropnop/kerbrute) |

## References

- [MITRE ATT&CK - Brute Force: Password Spraying (T1110.003)](https://attack.mitre.org/techniques/T1110/003/)
- [MITRE ATT&CK - Brute Force: Password Guessing (T1110.001)](https://attack.mitre.org/techniques/T1110/001/)
- [Microsoft - Event 4771 Documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4771)
