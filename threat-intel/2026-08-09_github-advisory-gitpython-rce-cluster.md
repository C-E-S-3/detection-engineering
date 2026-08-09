---
scraped_at: 2026-08-09T06:00:00Z
source_url: https://github.com/advisories/GHSA-wvpp-8hx9-p66j
report_type: vulnerability advisory
severity: high
title: "GitPython RCE Cluster: 6 Vulnerabilities in GitPython ≤ 3.1.57 — CI/CD Pipeline Exploitation Risk"
---

# GitPython RCE Cluster — Six Vulnerabilities Fixed in 3.1.58 (August 2026)

**Source:** GitHub Security Advisory Database (Multiple GHSAs)  
**Published:** 2026-08-04 (discovered); 2026-08-07 (reviewed in GitHub Advisory Database)  
**Severity:** High (CVSS 8.8 for worst-case)  

## Summary

A coordinated batch of **six security advisories** was published to the GitHub Advisory Database on 2026-08-07 for **GitPython** (the widely-used Python library wrapping git operations). All six vulnerabilities affect **GitPython ≤ 3.1.57** and are fixed in **3.1.58**. The cluster spans command injection, config injection, path traversal, arbitrary file overwrite, and arbitrary file read — a comprehensive attack surface review that collectively enables **Remote Code Execution (RCE) in CI/CD pipelines and developer toolchains** when GitPython processes untrusted input.

GitPython is downloaded approximately **100M times per month** from PyPI and is a transitive dependency in many CI/CD frameworks, security tools, and developer utilities.

## Vulnerability Details

### GHSA-wvpp-8hx9-p66j — Unsafe Option Guard Bypass via Single-Char kwarg Injection (CVSS 8.8, High)

GitPython's `_option_candidates` function only evaluates value-derived candidates when `split_single_char_options` is enabled. When disabled (which is not the default but can be set by callers), attackers can smuggle dangerous options as joined single-character tokens that bypass the unsafe-option denylist. For example:

```python
Repo.clone_from(src, dst,
    n="utouch /tmp/ACE;git-upload-pack",
    split_single_char_options=False)
# git interprets -nutouch /tmp/ACE;git-upload-pack as --upload-pack=<cmd>
```

**Impact:** Arbitrary OS command execution as the host process at `allow_unsafe_options=False` (the default). Affects all guarded methods that forward `**kwargs` to git.

---

### GHSA-jm78-9fvv-mhgr — Config Option Name Injection for SSH/Hook RCE (CVSS 8.8, High)

`_assure_config_name_safe()` filters only newlines, carriage returns, and null bytes from option **names** (not sections). Special characters (`=`, `#`, whitespace) are written verbatim into git config files. An attacker controlling an option name can inject config directives:

```python
with repo.config_writer() as cw:
    cw.set_value("core", "sshCommand = touch /tmp/RCE #", "x")
# Result in .git/config: core.sshCommand = touch /tmp/RCE
# RCE triggered on next SSH git operation
```

**Impact:** RCE via `core.sshCommand` on any SSH git operation, or via `core.hooksPath` pointing to attacker-controlled hooks directory.

---

### GHSA-hmq2-w58f-27jc — Submodule Name Path Traversal — Arbitrary Repository Creation (CVSS 8.2, High)

GitPython computes the on-disk location of a submodule's separate git directory directly from the `.gitmodules` section name with no path validation. A malicious repository can escape the clone directory:

```
[submodule "../../../../../../tmp/escaped_root/modules_dir"]
    path = legitimate_path
    url = https://attacker.example/
```

When a victim clones and runs `submodule_update(init=True)`, a fully initialized git repository is created at the attacker-specified path.

**Impact:** Arbitrary repository creation at filesystem paths controlled by the attacker; potential disk exhaustion; affects CI systems that auto-initialize submodules.

---

### GHSA-9rj7-rf2p-w77r — Repo.init() Template Option Hook Execution (CVSS 7.5, High)

`Repo.init()` forwards `**kwargs` verbatim to `git init` with no unsafe-option guard. Injecting `--template` causes git to copy malicious hooks from an attacker-controlled template directory into the newly initialized repository's `.git/hooks`:

```python
Repo.init("/victim/repo", template="/attacker/templates")
# .git/hooks/post-checkout (executable) copied and will auto-execute on checkout
```

**Impact:** Arbitrary code execution via git hook invocation on subsequent repository operations.

---

### GHSA-4gmw-gg2m-w46p — Unguarded read-tree Options — Arbitrary File Overwrite (High)

Forwarded `**kwargs` to `git read-tree` without unsafe-option guard validation allow injection of options like `--prefix` to write tree contents outside the expected target directory.

**Impact:** Arbitrary file overwrite in paths accessible by the git process.

---

### GHSA-hh9p-6wh2-4mfc — Arbitrary File Read via Pathspec Forwarding (CVSS 6.5, Moderate)

In `IndexFile.remove()` and `Head.checkout()`, when `--pathspec-from-file` is combined with `--pathspec-file-nul`, git treats the referenced file as a NUL-delimited pathspec. When a file does not match, git quotes it verbatim in the error message, leaking file contents through exception text.

**Impact:** Out-of-bounds file read via error output; confidentiality impact only.

---

## Affected Versions and Fix

| Status | Version |
|--------|---------|
| Vulnerable | GitPython ≤ 3.1.57 |
| Patched | GitPython 3.1.58 |

## Targeting

- **Platform:** Python applications, CI/CD pipelines, developer toolchains
- **Geography:** Global
- **Sectors:** All organizations using Python-based CI/CD, security tools, repository management, DevOps tooling
- **Attribution:** No active exploitation reported at time of publication; severity warrants immediate patching due to widespread CI/CD exposure

## IOCs

No threat-actor IOCs (IPs, domains, file hashes) are associated with these vulnerability disclosures. Indicators of exploitation would be observed at the process/filesystem layer (see associated detection rule).

## MITRE ATT&CK TTPs

| Technique | ID | Notes |
|-----------|----|-------|
| Command and Scripting Interpreter: Python | T1059.006 | Python applications calling vulnerable GitPython APIs process attacker-controlled input |
| Exploit Public-Facing Application | T1190 | CI/CD systems or developer tools running GitPython with untrusted repository input |
| Ingress Tool Transfer | T1105 | Hook execution or template injection could download additional payloads |
| Event Triggered Execution: Unix Shell Configuration Modification | T1546.004 | Malicious git hooks planted via template or hook-path injection persist across operations |
| Supply Chain Compromise: Compromise Software Dependencies | T1195.001 | Malicious git repositories or submodules triggering vulnerable GitPython code paths |

## Kill Chain

- **Exploitation** — Attacker provides malicious input (repo URL, submodule definition, kwargs) to a Python application using GitPython ≤ 3.1.57
- **Installation** — Malicious git hooks planted via template or hooksPath injection; arbitrary files written outside intended paths
- **Actions on Objectives** — Code execution in CI/CD runner, credential theft, lateral movement from build system

## Remediation

| Action | Priority |
|--------|----------|
| Upgrade GitPython to ≥ 3.1.58 in all environments | High |
| Audit requirements.txt, pyproject.toml, poetry.lock, Pipfile.lock for `gitpython` versions < 3.1.58 | High |
| Verify transitive dependency graphs (many tools depend on GitPython indirectly) | High |
| Ensure CI/CD pipelines processing untrusted repositories run with minimum-privilege accounts | Medium |
| Monitor Python processes spawning git with unusual arguments (see detection rule) | Medium |

## References

- [GHSA-wvpp-8hx9-p66j — Option Guard Bypass (CVSS 8.8)](https://github.com/advisories/GHSA-wvpp-8hx9-p66j)
- [GHSA-jm78-9fvv-mhgr — Config Option Name Injection (CVSS 8.8)](https://github.com/advisories/GHSA-jm78-9fvv-mhgr)
- [GHSA-hmq2-w58f-27jc — Submodule Path Traversal (CVSS 8.2)](https://github.com/advisories/GHSA-hmq2-w58f-27jc)
- [GHSA-9rj7-rf2p-w77r — Template Option Hook Execution (CVSS 7.5)](https://github.com/advisories/GHSA-9rj7-rf2p-w77r)
- [GHSA-4gmw-gg2m-w46p — Unguarded read-tree File Overwrite](https://github.com/advisories/GHSA-4gmw-gg2m-w46p)
- [GHSA-hh9p-6wh2-4mfc — Pathspec Arbitrary File Read (CVSS 6.5)](https://github.com/advisories/GHSA-hh9p-6wh2-4mfc)
- [GitPython 3.1.58 Release](https://github.com/gitpython-developers/GitPython/releases/tag/3.1.58)
- [MITRE ATT&CK — T1059.006: Python](https://attack.mitre.org/techniques/T1059/006/)
- [MITRE ATT&CK — T1195.001: Supply Chain Compromise: Software Dependencies](https://attack.mitre.org/techniques/T1195/001/)
