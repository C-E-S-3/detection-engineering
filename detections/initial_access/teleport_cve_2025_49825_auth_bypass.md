# Detection: Teleport Authentication Bypass / Unauthorized Access

**Rule IDs:** 103100–103129
**Rule File:** `wazuh/rules/teleport_security.xml`
**Decoder File:** `wazuh/decoders/teleport_audit.xml`
**MITRE ATT&CK:** T1078, T1110, T1098, T1550, T1136, T1499

## What It Detects

Unauthorized access, brute-force, and privilege abuse via the Teleport access
platform. Anchors on CVE-2025-49825 (auth bypass) patterns but provides
general Teleport security monitoring coverage.

## Log Source

Teleport audit log (`/var/lib/teleport/log/events.log`) in JSON-lines format,
read by Wazuh agent with `log_format: json`. Also handles syslog-forwarded
Teleport events (`program_name: teleport`).

**Required Wazuh localfile config (deploy via Ansible `wazuh-agent` role):**
```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/lib/teleport/log/events.log</location>
</localfile>
```

## Rule Summary

| Rule ID | Severity | Description |
|---------|----------|-------------|
| 103100 | 0 (base) | Teleport audit event (JSON) |
| 103101 | 0 (base) | Teleport audit event (syslog) |
| 103102 | 5 (low) | Single auth failure |
| 103103 | 11 (high) | Brute-force: 5+ failures in 60s |
| 103104 | 12 (high) | Credential stuffing: 5+ users from same IP |
| 103110 | 11 (high) | Session with non-user certificate type |
| 103111 | 10 (medium) | Session from external IP |
| 103112 | 12 (high) | Cert flood: 10+ cert.create in 60s |
| 103120 | 8 (medium) | New role created |
| 103121 | 11 (high) | Privileged role created |
| 103122 | 8 (medium) | New user account created |
| 103123 | 12 (high) | Bot/machine account created |
| 103124 | 8 (medium) | Join token created |
| 103125 | 12 (high) | Root session started |
| 103126 | 8 (medium) | Login outside business hours |
| 103127 | 10 (medium) | Sudo executed in Teleport session |
| 103128 | 11 (high) | Teleport service crash |
| 103129 | 13 (critical) | Teleport service crash loop (3+ in 5 min) |

## False Positive Guidance

- **103103** (brute-force): May trigger on legitimate password reset flows. Tune threshold or allowlist known IP ranges.
- **103111** (external IP): Expected if Teleport is used for remote access. Allowlist trusted CIDR ranges.
- **103120** (role create): Expected during onboarding. Filter by known admin users.
- **103125** (root session): May trigger on legitimate infrastructure automation. Add allowlist for service accounts.
- **103126** (after-hours): Adjust time window to match organization's operating hours.

## Response Playbook

1. Alert fires on **103103/103104** (brute-force): Block source IP in OPNsense, check for successful subsequent login.
2. Alert fires on **103110/103112** (cert anomaly): Immediately audit all active sessions in Teleport UI, revoke suspect certs.
3. Alert fires on **103121** (privileged role): Audit role permissions, verify creating user's identity.
4. Alert fires on **103129** (crash loop): Isolate Teleport node, check for exploit payload delivery, restore from known-good state.
