# LiteLLM MCP Preview Endpoint OS Command Injection (CVE-2026-42271 + CVE-2026-48710)

## Summary

| Field | Value |
|-------|-------|
| CVEs | CVE-2026-42271 (BerriAI LiteLLM), CVE-2026-48710 (Starlette BadHost) |
| CVSS | 8.7 (High) — escalates to Unauthenticated RCE when chained |
| CISA KEV | Added 2026-06-08; Federal deadline 2026-06-22 |
| MITRE | T1190 (Exploit Public-Facing Application), T1552 (Unsecured Credentials), T1078 (Valid Accounts) |
| Severity | Critical when chained |
| Affected Versions | LiteLLM >= 1.74.2 and < 1.83.7; Starlette <= 1.0.0 |
| Patched Version | LiteLLM 1.83.7+ |
| Wazuh Rules | 102100-102112 (`wazuh/rules/litellm_cve_2026_42271_mcp_rce.xml`) |

## Vulnerability Description

### CVE-2026-42271 — LiteLLM MCP stdio Transport Command Injection

LiteLLM's MCP server preview feature exposes two unauthenticated (or auth-bypassed) endpoints that accept a full MCP stdio transport configuration in the request body:

- `POST /mcp-rest/test/connection`
- `POST /mcp-rest/test/tools/list`

Both endpoints accept a JSON body with `command`, `args`, and `env` fields that describe an MCP server stdio transport. LiteLLM executes this as a subprocess — allowing an attacker to run arbitrary OS commands on the LiteLLM host. The exploit body looks like:

```json
{
  "transport": {
    "type": "stdio",
    "command": "/bin/sh",
    "args": ["-c", "id; cat /etc/passwd; env | grep -i 'key\\|token\\|secret'"],
    "env": {}
  }
}
```

The primary impact is exfiltration of LLM provider API keys (OpenAI, Anthropic, Azure OpenAI), cloud credentials, and CI/CD tokens stored by the LiteLLM proxy configuration.

### CVE-2026-48710 — Starlette BadHost Authentication Bypass

Starlette <= 1.0.0 contains a host-header validation bypass that allows unauthenticated access to protected routes when LiteLLM's auth middleware relies on Starlette's host-based routing. When both vulnerabilities are present, authenticated OS command injection degrades to **unauthenticated** OS command injection.

## Attack Flow

```
1. Attacker discovers LiteLLM instance (via /health, /v1/models, or /mcp-rest/ GET)
2. Attacker POSTs to /mcp-rest/test/connection with malicious stdio config
   [Optional] CVE-2026-48710: crafted Host header bypasses auth middleware
3. LiteLLM executes attacker-controlled command as subprocess
4. Attacker collects API keys from env output, then POSTs to /key/list to enumerate virtual keys
5. Stolen keys used to abuse LLM provider APIs (billing fraud, data extraction, further pivoting)
```

## Detection Logic

### Wazuh Rules (102100-102112)

| Rule ID | Level | Description |
|---------|-------|-------------|
| 102100 | 13 | POST to `/mcp-rest/test/connection` |
| 102101 | 13 | POST to `/mcp-rest/test/tools/list` |
| 102102 | 15 | 2xx response from `/mcp-rest/test/connection` (RCE success) |
| 102103 | 15 | 2xx response from `/mcp-rest/test/tools/list` (RCE success) |
| 102104 | 10 | Any HTTP request to `/mcp-rest/` namespace |
| 102105 | 13 | 3+ `/mcp-rest/` requests from same IP in 60s (scanner) |
| 102106 | 13 | 3+ sources targeting same host in 120s (distributed scan) |
| 102107 | 12 | Malformed Host header in MCP request (CVE-2026-48710 auth bypass) |
| 102109 | 12 | Access to `/key/generate\|info\|list` after MCP probe (key harvest) |
| 102110 | 10 | Access to `/health\|config\|v1/models` (AI gateway reconnaissance) |
| 102111 | 15 | MCP probe + key harvest from same source within 300s (two-stage exploit) |
| 102112 | 9 | GET to `/mcp-rest/` namespace (fingerprinting) |

### Log Source

Traefik JSON access logs (decoded via Wazuh built-in JSON decoder). Key fields used:
- `RequestMethod`, `RequestPath`, `RequestHost`, `DownstreamStatus`, `ClientHost`

## Investigation Playbook

1. **Identify source IP** from `ClientHost` in triggering event
2. **Check for 2xx response** (rules 102102/102103) — if present, treat as confirmed exploitation
3. **Review Traefik logs** for `/key/*` access from same IP within 300s of MCP probe
4. **Check LiteLLM process logs** for subprocess execution (look for unexpected child processes)
5. **Rotate API keys immediately** if exploitation confirmed:
   - OpenAI: revoke via dashboard.openai.com
   - Anthropic: revoke via console.anthropic.com
   - Azure OpenAI: revoke via Azure portal
6. **Patch or isolate** — upgrade to LiteLLM 1.83.7+, update Starlette > 1.0.0

## Mitigation

1. **Patch**: Upgrade LiteLLM to >= 1.83.7 (enforces `PROXY_ADMIN` role on affected endpoints)
2. **Patch Starlette**: Update to Starlette > 1.0.0 to prevent BadHost auth bypass
3. **Network isolation**: LiteLLM should not be directly exposed to the internet; place behind authenticated reverse proxy
4. **Firewall**: Block external access to `/mcp-rest/` endpoints at Traefik middleware layer
5. **Secret rotation**: Treat any externally accessible LiteLLM instance as potentially compromised

## References

- [CISA KEV Alert 2026-06-08](https://www.cisa.gov/news-events/alerts/2026/06/08/cisa-adds-two-known-exploited-vulnerabilities-catalog)
- [NVD CVE-2026-42271](https://nvd.nist.gov/vuln/detail/CVE-2026-42271)
- [NVD CVE-2026-48710](https://nvd.nist.gov/vuln/detail/CVE-2026-48710)
- Threat intel: `threat-intel/2026-06-08_cisa-kev-checkpoint-cve-2026-50751-litellm-cve-2026-42271.md`
