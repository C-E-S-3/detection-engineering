---
scraped_at: 2026-07-12T00:00:00Z
source_url: https://socket.dev/blog/jscrambler-supply-chain-attack
report_type: threat-intel
severity: high
title: "jscrambler npm Package Compromised in Cross-Platform Rust Infostealer Supply Chain Attack"
tags:
  - supply-chain
  - npm
  - infostealer
  - rust
  - T1195.002
  - T1059.007
  - T1053.005
---

# jscrambler npm Package Compromised in Cross-Platform Rust Infostealer Supply Chain Attack

**Source:** [Socket.dev — jscrambler supply chain attack](https://socket.dev/blog/jscrambler-supply-chain-attack)  
**Reported:** 2026-07-11  
**Severity:** High  

---

## Summary

The `jscrambler` npm package — a legitimate JavaScript obfuscation utility with a large install base — was compromised across five malicious versions (8.14.0, 8.16.0, 8.17.0, 8.18.0, 8.20.0). Attackers injected a malicious `preinstall` hook into `package.json` pointing to `dist/setup.js`. When a developer or CI/CD pipeline runs `npm install`, the hook executes, fingerprints the host OS, and silently drops a platform-specific Rust-compiled infostealer binary (Linux ELF, Windows PE64, macOS arm64 Mach-O). The binary steals browser credential stores (Chrome, Brave, Edge, Chromium), the Bitwarden browser extension vault, and Steam session tokens, then establishes persistence via Windows Task Scheduler or macOS LaunchAgents. C2 communication is encrypted at runtime using keys embedded in the Rust binary and was not recoverable via static analysis.

---

## Affected Versions

| Version | Status |
|---------|--------|
| 8.14.0 | Malicious — contains preinstall hook |
| 8.16.0 | Malicious — contains preinstall hook |
| 8.17.0 | Malicious — contains preinstall hook |
| 8.18.0 | Malicious — contains preinstall hook |
| 8.20.0 | Malicious — contains preinstall hook |

Versions 8.13.x and earlier are clean. 8.15.0, 8.19.0 were skipped in the malicious sequence. Organizations should audit `package-lock.json`, `yarn.lock`, and `pnpm-lock.yaml` files for any of the affected versions.

---

## Attack Chain

1. **Compromise**: Attacker gained write access to the `jscrambler` npm registry account (method unknown at time of reporting).
2. **Preinstall Hook Injection**: Malicious `dist/setup.js` registered as `preinstall` script in `package.json`.
3. **OS Fingerprinting**: `setup.js` calls `process.platform` to select the appropriate binary.
4. **Binary Drop**: Rust-compiled infostealer binary written to a temporary path and made executable.
5. **Execution**: Binary runs immediately, targeting browser credential stores, Bitwarden extension, Steam sessions.
6. **Persistence**:
   - **Windows**: `schtasks.exe` creates a scheduled task to re-run the binary at logon.
   - **macOS**: LaunchAgent plist written to `~/Library/LaunchAgents/`.
   - **Linux**: No persistence observed in analyzed samples.
7. **Exfiltration**: Stolen data sent to C2 over encrypted channel; C2 address decrypted at runtime from embedded key material.

---

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access, Execution, Persistence |
| Technique | T1195.002 — Compromise Software Supply Chain |
| Technique | T1059.007 — JavaScript |
| Technique | T1053.005 — Scheduled Task (Windows persistence) |
| Technique | T1547.011 — Plist Modification (macOS LaunchAgent persistence) |
| Technique | T1555.003 — Credentials from Web Browsers |

---

## IOCs

### File Hashes (SHA256)

| Hash | Description |
|------|-------------|
| `a742de963f14a92d24ebcbc7b44ac867e23a20d31d1b0094a13a4f83287f4e60` | `dist/setup.js` — malicious preinstall hook (found in all 5 affected versions) |
| `a41a523ef9517aab37ed6eea0ec881821bdcb7aefcb5c5f603adc7907f868c86` | `dist/intro.js` — secondary loader stage |
| `fbbcf4d8f98168f78f5c0c47a9ae56d59ec8ac84a7c9ca6b797fedfb8d62d2bd` | Linux ELF Rust infostealer payload |
| `b7ca95d1b23c8e67416a25cedf741de0917c2096bbc9d24649eea7853d054903` | Windows PE64 Rust infostealer payload |
| `c8fd47d36bdf7c825378593ab82ed8c24d1dc52e26b507812393e24e1d5201fd` | macOS arm64 Mach-O Rust infostealer payload |

### Network Indicators

C2 address encrypted at runtime; no static network IOCs recoverable. Monitor for anomalous outbound HTTPS connections from `node.exe` or `npm.cmd` process trees.

---

## Detection Notes

The highest-confidence behavioral signal is `node.exe` spawning `schtasks.exe` — npm's JavaScript execution model has no legitimate reason to invoke the Windows Task Scheduler. Secondary signals include `node.exe` spawning `cmd.exe` or `powershell.exe` during a package install lifecycle event.

See detection: [jscrambler npm Malicious Preinstall Hook Infostealer](../detections/execution/jscrambler_npm_malicious_preinstall_hook_infostealer.md)

---

## Threat Actor

Unknown. Attribution not established at time of reporting. The attack is consistent with financially motivated supply chain compromise for credential harvesting. No overlap with named threat actors identified.

---

## Remediation

1. Audit all `package-lock.json`, `yarn.lock`, and `pnpm-lock.yaml` files for jscrambler versions 8.14.0, 8.16.0, 8.17.0, 8.18.0, 8.20.0.
2. Pin to a clean version (≤8.13.x or a verified clean release post-remediation).
3. Search for the scheduled task created by the Windows payload: look for tasks pointing to paths in `%TEMP%` or `%APPDATA%` directories.
4. Check for LaunchAgent plists in `~/Library/LaunchAgents/` referencing unknown executables.
5. Rotate browser-stored credentials for Chrome, Brave, Edge, and Chromium profiles on any developer workstation that installed an affected version.
6. Rotate Bitwarden master passwords and invalidate active sessions if Bitwarden browser extension was installed.
7. Revoke and re-issue Steam session tokens.
8. Treat any CI/CD agent that ran `npm install` with an affected version as fully compromised; rotate all secrets accessible from that environment.

---

## References

- [Socket.dev — jscrambler supply chain attack](https://socket.dev/blog/jscrambler-supply-chain-attack)
- [MITRE ATT&CK — T1195.002 Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/002/)
- [MITRE ATT&CK — T1059.007 JavaScript](https://attack.mitre.org/techniques/T1059/007/)
- [MITRE ATT&CK — T1053.005 Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)
