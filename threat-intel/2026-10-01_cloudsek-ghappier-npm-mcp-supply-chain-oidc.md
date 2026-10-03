---
scraped_at: "2026-10-03T00:00:00Z"
source_url: "https://www.cybersecuritynews.com/ghappier-mcp-supply-chain-attack/"
report_type: threat-intel
severity: high
title: "GHAPPIER: npm MCP Server Supply Chain Attack Abusing GitHub Actions OIDC Trusted Publishing"
tags:
  - npm
  - supply-chain
  - mcp-server
  - oidc
  - github-actions
  - trusted-publishing
  - initial-access
  - dforge-mcp
---

# GHAPPIER: npm MCP Server Supply Chain Attack Abusing GitHub Actions OIDC Trusted Publishing

## Executive Summary

CloudSEK and independent security researchers disclosed "GHAPPIER," a supply chain attack targeting AI/LLM developer tooling via a poisoned npm Model Context Protocol (MCP) server package. The attacker compromised the `@dforge-core/dforge-mcp` npm package by exploiting GitHub Actions OIDC trusted publishing to push malicious code through a legitimately signed release pipeline — bypassing typical supply chain safeguards that flag unsigned or unverified package pushes.

The malicious version `@dforge-core/dforge-mcp@0.2.21` contained a four-stage self-deleting loader that only executes when the MCP server is explicitly launched, deliberately avoiding activation during `npm install` to evade CI/CD security scanning. The scope of exposure spans 65 GitHub repositories and 73 files across 22 accounts.

This attack is notable for two reasons: (1) it represents the first observed weaponization of GitHub Actions OIDC trusted publishing for npm supply chain compromise; and (2) it specifically targets the emerging MCP server ecosystem, where packages execute with broad tool-use permissions over AI coding assistants.

---

## Attack Details

### Vulnerability Exploited

The attacker abused GitHub's npm OIDC Trusted Publishing feature, which allows maintainers to publish npm packages directly from GitHub Actions workflows without storing long-lived npm tokens. By compromising or creating a malicious GitHub Actions workflow in the `@dforge-core/dforge-mcp` repository, the attacker was able to publish a new package version that was cryptographically signed by GitHub's OIDC provider — indistinguishable in provenance from legitimate releases.

**Why this matters**: npm package provenance via OIDC trusted publishing is a newer supply chain defense. Attackers have now demonstrated they can weaponize this trust mechanism rather than just bypass it.

### Malicious Package

| Field | Value |
|-------|-------|
| Package | `@dforge-core/dforge-mcp` |
| Malicious Version | `0.2.21` |
| Clean Version | `0.2.22` (patched, released after discovery) |
| Registry | npmjs.com |
| Ecosystem | Node.js / MCP (Model Context Protocol) |

### Attack Chain (Four-Stage Loader)

1. **Stage 0 — Dormancy**: The malicious postinstall hook performs a context check. If the process is a plain `npm install` (no MCP invocation context), execution terminates. This bypasses automated supply chain scanners that run `npm install` in sandboxes.

2. **Stage 1 — Environment Fingerprinting**: When the MCP server is launched (e.g., from an AI coding assistant like Cursor or Claude), the loader fingerprints the environment, collecting CI/CD tokens, SSH keys, cloud credentials, and IDE configuration.

3. **Stage 2 — Remote Staging**: An obfuscated XHR fetches a second-stage payload from a Vercel deployment domain (specific subdomain not publicly disclosed; gated in CloudSEK full report).

4. **Stage 3 — Self-Deletion**: The loader removes itself from the installed package to hinder forensic recovery. The payload installs a persistent C2 mechanism.

### Scope

| Metric | Value |
|--------|-------|
| Malicious GitHub repos | 65 |
| Malicious files | 73 |
| GitHub accounts involved | 22 |
| Discovery date | ~2026-10-01 |
| Disclosure | CloudSEK / independent researchers, October 2026 |

---

## TTPs (MITRE ATT&CK)

| Tactic | Technique | Description |
|--------|-----------|-------------|
| Initial Access | T1195.002 — Supply Chain Compromise: Compromise Software Supply Chain | Malicious npm package version published via compromised GitHub Actions OIDC workflow |
| Execution | T1059.007 — Command and Scripting Interpreter: JavaScript | Four-stage Node.js loader executes in MCP server context |
| Defense Evasion | T1027.002 — Obfuscated Files or Information: Software Packing | Loader stages are obfuscated; self-deletion in stage 3 removes evidence |
| Defense Evasion | T1480.001 — Execution Guardrails: Environmental Keying | Stage 0 dormancy check: payload only activates in MCP server invocation context, not during npm install |
| Collection | T1552.001 — Unsecured Credentials: Credentials in Files | Harvests SSH keys, cloud credentials, IDE tokens from developer environment |
| Command and Control | T1102 — Web Service | C2 staging via Vercel deployment infrastructure (legitimate CDN used as C2 relay) |

## Lockheed Martin Kill Chain

- **Delivery**: Malicious npm package pushed via OIDC trusted publishing pipeline
- **Exploitation**: Self-activating loader in MCP server runtime context
- **Installation**: Persistent C2 mechanism installed post-execution
- **Actions on Objectives**: Credential and secret exfiltration from developer environments

---

## IOCs

**Note**: Full atomic IOCs (C2 domain, specific Vercel subdomain, payload hashes) have not been publicly released as of October 3, 2026 — CloudSEK's full IOC set is gated behind their threat intelligence platform. The below represents the confirmed public IOCs.

### Package Indicators

| Indicator | Type | Context |
|-----------|------|---------|
| `@dforge-core/dforge-mcp@0.2.21` | npm package | Malicious version; self-deleting four-stage loader |
| `@dforge-core/dforge-mcp@0.2.22` | npm package | Patched clean version released after discovery |

### Network Indicators

No public C2 IPs, domains, or Vercel subdomains have been disclosed at time of writing.

---

## Detection Guidance

Since full atomic IOCs are not yet public, detection should focus on behavioral patterns:

1. **npm package lock file audit**: Scan all `package-lock.json` and `yarn.lock` files for `@dforge-core/dforge-mcp@0.2.21`. The presence of this version in any lockfile is a confirmed IOC.

2. **MCP server process behavior**: Alert on Node.js processes spawning from MCP server binaries (`dforge-mcp`, `@dforge-core/dforge-mcp`) that make unexpected outbound network connections or spawn shell child processes.

3. **OIDC trusted publishing abuse (proactive)**: Monitor GitHub Actions workflow runs in your organization for unexpected npm publish steps using the `id-token: write` OIDC permission on repositories that should not be publishing npm packages.

4. **Credential access patterns**: Monitor for post-execution signs of credential harvesting — new outbound HTTPS connections from developer workstations/CI agents to Vercel domains with non-standard paths, SSH key reads, or cloud CLI credential file access.

**Splunk query (package lock file scan via endpoint filesystem):**

```spl
`crowdstrike` source="crowdstrike:fdr:ProcessRollup2"
| search CommandLine="*dforge-mcp*0.2.21*" OR CommandLine="*@dforge-core*0.2.21*"
| table _time, ComputerName, UserName, CommandLine, SHA256HashData
| sort -_time
```

**Splunk query (MCP server spawning unexpected children):**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.parent_process IN ("*dforge-mcp*", "*dforge-core*")
  AND Processes.process_name IN ("sh", "bash", "zsh", "cmd.exe", "powershell.exe", "curl", "wget", "python*")
by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=80
| table firstTime lastTime dest user parent_process_name parent_process process_name process risk_score
```

---

## Threat Actor Attribution

No attribution has been made as of October 3, 2026. The campaign's focus on AI developer tooling (MCP servers) and the precision of the execution guard (activates only in MCP server context) suggests a technically sophisticated actor. Targeting of developer credential stores (SSH keys, cloud tokens, IDE API keys) is consistent with DPRK IT Worker / Lazarus financial motivation patterns, but this is speculative.

---

## Remediation

1. **Immediate**: Audit all `package-lock.json` and `yarn.lock` files for `@dforge-core/dforge-mcp@0.2.21`. If found, treat the host as compromised.
2. **Update**: Upgrade to `@dforge-core/dforge-mcp@0.2.22` or later.
3. **Rotate credentials**: Any developer/CI host that installed and invoked version `0.2.21` should rotate all secrets: SSH keys, cloud API credentials, npm tokens, IDE API keys.
4. **Audit CI/CD**: Review GitHub Actions workflows in your organization for unexpected `id-token: write` OIDC permissions on npm-publishing steps.
5. **MCP server hygiene**: Apply the same dependency vetting rigor to MCP servers as to production dependencies — they execute with tool-use permissions over AI coding environments.

---

## References

- [CybersecurityNews — GHAPPIER MCP Supply Chain Attack](https://www.cybersecuritynews.com/ghappier-mcp-supply-chain-attack/)
- [MITRE ATT&CK T1195.002 — Supply Chain Compromise: Compromise Software Supply Chain](https://attack.mitre.org/techniques/T1195/002/)
- [MITRE ATT&CK T1480.001 — Execution Guardrails: Environmental Keying](https://attack.mitre.org/techniques/T1480/001/)
- [npm OIDC Trusted Publishing Documentation](https://docs.npmjs.com/generating-provenance-statements)
- [Model Context Protocol Specification](https://modelcontextprotocol.io/specification)
