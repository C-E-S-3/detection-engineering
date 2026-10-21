# Sigma rules

Detections in [Sigma](https://sigmahq.io) format, deployed to an OpenSearch
Security Analytics backend as **custom rules**. One directory per Security Analytics
log type — the directory name is the rule category:

```
sigma/
├── linux/      # auditd (Security Analytics `linux` log type)
├── windows/    # Windows event logs
└── traefik/    # Traefik JSON access log (custom log type)
```

## Conventions

Every rule must have:

| Field | Requirement |
|---|---|
| `id` | a fresh UUIDv4 (never reuse; it is the rule's identity across updates) |
| `title`, `description`, `author` | descriptive; `title` must be unique |
| `date` (and `modified` when changed) | `YYYY/MM/DD` — **required** by Security Analytics |
| `status` | `experimental` → `test` → `stable` as the rule proves itself |
| `level` | `informational` / `low` / `medium` / `high` / `critical` |
| `tags` | ATT&CK tags (`attack.tXXXX`, tactic names); every tag must be `namespace.value` |
| `falsepositives` | known benign triggers |

Field names:

- **linux (auditd):** raw auditd names as standard Sigma auditd rules use them
  (`type`, `syscall`, `key`, `exe`, `comm`, `a0`…`a7`, `cwd`, `name`), and
  `process.command_line` / `process.exe` for process-creation style rules.
- **windows:** standard Sigma Windows field names (`EventID`, `Image`, `CommandLine`, …).
- **traefik:** ECS names — `url.path`, `url.domain`, `http.request.method`,
  `http.response.status_code`, `source.ip`, `user_agent.original`.

Keep rules generic: no environment-specific hostnames, addresses or account names
(those belong in a private rule set).

## Lifecycle

New rules land as `status: experimental`. Promote to `test` after a clean run
against real data, and to `stable` once the false-positive rate is known.
