---
scraped_at: 2026-07-24T08:00:00Z
source_url: https://blog.talosintelligence.com/chaos-msarat-browser-cdp-webrtc-c2/
report_type: threat-intel
severity: high
title: "Chaos / msaRAT: Novel Browser-Resident C2 via Chrome DevTools Protocol and WebRTC"
---

# Chaos / msaRAT — Browser-Resident C2 via Chrome DevTools Protocol + WebRTC

**Source:** Cisco Talos Intelligence Group  
**Published:** 2026-07-23  
**Severity:** High  

## Summary

Cisco Talos published research on **msaRAT**, a new RAT distributed by the **Chaos** malware family, notable for using an unconventional C2 channel that routes all implant communication through the victim's own browser process via the Chrome DevTools Protocol (CDP) and WebRTC. Because the resulting traffic is technically generated *by the browser itself*, it bypasses network controls that inspect the originating process and makes attribution to a malicious parent process impossible through traditional means.

### Attack Flow

1. **Delivery**: Victims are lured to a malicious landing page (e.g., a fake Microsoft Update portal or trojanized software download).
2. **Staging**: An MSI installer (`update_ms.msi`) is delivered via `curl` to the victim host from `172.86.126.18:443` at path `/update_ms.msi`.
3. **Execution**: The MSI drops and executes the Chaos dropper, which injects msaRAT into the running browser process.
4. **C2 Establishment**: msaRAT attaches to the browser via CDP (loopback `127.0.0.1:9222` or equivalent remote debugging port), then uses the browser's WebRTC stack to establish a peer connection to the attacker's signaling server at `is-01-ast.ols-img-12.workers.dev` (a Cloudflare Workers endpoint). All implant traffic exits via the browser's network identity.

### Why This Matters

- **Process-based network controls are bypassed**: EDR/NGFW rules filtering by originating process see `chrome.exe` or `msedge.exe` — a trusted process — not the malicious loader.
- **TLS certificate pinning irrelevant**: The WebRTC DTLS handshake uses browser-managed certificates; browser TLS inspection has no effect.
- **WebRTC is rarely logged**: Most proxy/firewall solutions do not log WebRTC STUN/TURN traffic in a way that associates it with process or file context.
- **Cloudflare Workers signaling server**: The domain `is-01-ast.ols-img-12.workers.dev` is a Cloudflare Workers URL, meaning it shares IP space with millions of legitimate Cloudflare-hosted applications. IP blocklisting is impractical.

## IOCs

### IP Addresses

| Indicator | Type | Context |
|-----------|------|---------|
| `172.86.126.18` | IPv4 | msaRAT staging server; payload delivered at `/update_ms.msi` via HTTPS on port 443 |

### Domains

| Indicator | Type | Context |
|-----------|------|---------|
| `is-01-ast.ols-img-12.workers.dev` | Domain | msaRAT WebRTC signaling C2 via Cloudflare Workers; receives implant beacon and delivers operator tasking over WebRTC data channel |

## MITRE ATT&CK TTPs

| Technique | ID | Notes |
|-----------|----|-------|
| Process Injection | T1055 | msaRAT injected into browser process to access CDP and browser network stack |
| Browser in the Middle | T1555 | CDP attachment to running browser |
| Web Service: One-Way Communication | T1102.001 | Cloudflare Workers endpoint used as signaling relay |
| Application Layer Protocol: Web Protocols | T1071.001 | WebRTC data channel over DTLS encapsulated in browser WebRTC stack |
| Ingress Tool Transfer | T1105 | MSI payload staged on `172.86.126.18:443/update_ms.msi` |
| Masquerading | T1036 | Fake Microsoft Update MSI filename (`update_ms.msi`) |

## Kill Chain

- **Delivery** — Malicious download portal or social engineering
- **Exploitation** — MSI execution
- **Installation** — msaRAT injected into browser process via CDP
- **Command & Control** — WebRTC peer channel through browser to Cloudflare Workers signaling server

## Attribution

**Chaos** malware family; threat actor identity not publicly confirmed by Talos as of publication date. Chaos has been used by multiple actors for ransomware and espionage operations.

## References

- [Cisco Talos — Chaos/msaRAT Browser CDP WebRTC C2 (2026-07-23)](https://blog.talosintelligence.com/chaos-msarat-browser-cdp-webrtc-c2/)
- [Talos GitHub IOC file (raw)](https://raw.githubusercontent.com/Cisco-Talos/IOCs/main/2026/07/chaos-msarat.txt)
- [MITRE ATT&CK — T1055: Process Injection](https://attack.mitre.org/techniques/T1055/)
- [MITRE ATT&CK — T1102.001: Web Service: One-Way Communication](https://attack.mitre.org/techniques/T1102/001/)
- [MITRE ATT&CK — T1071.001: Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
