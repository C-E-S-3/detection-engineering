# Sigma rules

Detections in [Sigma](https://sigmahq.io) format, deployed to an OpenSearch
Security Analytics backend as **custom rules**. One directory per Security Analytics
log type — the directory name is the rule category:

```
sigma/
├── linux/      # auditd (Security Analytics `linux` log type)
├── windows/    # Windows event logs
├── dns/        # DNS queries from the resolvers
├── opnsense/   # OPNsense pf filter log (custom log type)
├── idp/        # identity provider application logs (custom log type)
├── traefik/    # Traefik JSON access log (custom log type)
├── wazuh/      # Wazuh alerts.json (custom log type, siem-wazuh-alerts)
└── pam/        # PAM / bastion audit: JumpServer + Teleport (custom log type, siem-pam)
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
| `tags`: `risk.score.N` | one per rule, `N` = 0-100: see [Risk score](#risk-score) |
| `falsepositives` | known benign triggers |

Field names:

- **linux (auditd):** raw auditd names as standard Sigma auditd rules use them
  (`type`, `syscall`, `key`, `exe`, `comm`, `a0`…`a7`, `cwd`, `name`), and
  `process.command_line` / `process.exe` for process-creation style rules.
- **windows:** standard Sigma Windows field names (`EventID`, `Image`, `CommandLine`, …).
- **traefik:** ECS names — `url.path`, `url.domain`, `http.request.method`,
  `http.response.status_code`, `source.ip`, `user_agent.original`. The raw access-log
  fields are kept under `traefik.*`: `traefik.ServiceName` / `traefik.RouterName`
  (absent when no router matched) and `traefik.OriginStatus` (status the backend
  returned, `0` when no backend answered; present on every event, so safe to negate).
- **wazuh:** raw alerts.json names. FIM path is `syscheck.path`.
- **pam:** ECS names shared by every product: `event.module` (`jumpserver`,
  `teleport`), `event.dataset`, `event.action`, `event.outcome`, `event.category`,
  `user.name`, `user.target.name`, `source.ip`, `destination.*`,
  `process.command_line` (session commands); product fields under
  `jumpserver.<category>.*` (e.g. `jumpserver.session_command.risk_level`,
  `jumpserver.operation.resource_type`, `jumpserver.login.reason`) and `teleport.*`.

Keep rules generic: no environment-specific hostnames, addresses or account names
(those belong in a private rule set).

## Risk score

`level` decides whether one finding alerts by itself: detectors notify on `high` and
`critical` only. The risk score is the second path. A rule states how much **one
firing** adds to the risk of the entity it fired for (the host for host telemetry,
the client address for network and proxy telemetry) with a tag:

```yaml
tags:
  - attack.discovery
  - attack.t1082
  - risk.score.25
```

Every scored finding becomes a risk event. Risk is summed per entity over a rolling
24 hours, and an entity whose sum reaches the threshold (100 by default) raises one
alert. A rule counts once per entity per 24 hours however often it fires, so a noisy
rule cannot reach the threshold alone: it takes several different rules on the same
entity. This is what makes a `low` or `medium` rule worth keeping: silent alone,
decisive in combination.

Choosing `N` (the tiers of the repository guide, read as "how sure am I that one
firing is malicious, and how bad is it if so"):

| Score | Use for |
|---|---|
| 90-100 | near-certain malicious; one firing should alert (normally also `level: critical`) |
| 75-89 | strong indicator; one more weak signal on the entity should alert |
| 50-74 | suspicious; two of these on one entity in a day should alert |
| 25-49 | anomalous but often benign (admin tooling, discovery commands); useful only with others |
| 1-24 | context; many must coincide |
| 0 | never contributes (say why in a comment) |

- The score is independent of `level`. A `medium` rule with many benign backtest hits
  belongs at 25, not 50. Lower the score for every benign hit class the backtest shows
  that the rule cannot filter out.
- Exactly one `risk.score.N` tag per rule, integer 0-100. `risk.40`, `risk.score.high`
  or two score tags fail the lint and block the push.
- A rule without the tag adds no risk. That is the right choice for a rule nobody has
  scored yet; do not guess a number to fill the field.
- Changing a score is a rule change: bump `modified` and say why in the PR.

## Security Analytics compile gotchas

Security Analytics compiles Sigma itself and does not implement all of it. A rule can
pass lint, be accepted by the API and still never match, or match everything. Always
read the **compiled query** from the backtest, not just the hit count.

- **A negated field gets `AND _exists_: <field>`.** `not filter` on a field that some
  events lack silently drops those events from the rule. Negate only fields that are
  on every event you want to keep; match optional fields positively, e.g.
  `selection and (selection_optional or not filter_always_present)`.
- **No numeric comparison modifiers.** `|gt`, `|gte`, `|lt`, `|lte` compile to a text
  comparison and never match. List the values or express the logic another way.
- **No aggregations.** `count() by x > N` is stored without the count, so the rule
  matches every event that hits the selection. Do not write frequency rules.
- **Bare keywords match inside ordinary words.** `contains: 'drop'` fires on
  `Backdrop`, `select` on `select2.js`. Anchor a keyword to what must surround it in
  the attack (a separator, an operator, a path boundary).
- **`*` and `?` in a value are wildcards.** `'DROP/*'` means "DROP/ then anything".
  Write a literal asterisk as `\*` and check the compiled query shows `\*`.
- **Prefix matches are greedy.** `url.path|startswith: '/dashboard'` also matches
  `/dashboards` and every application page under that prefix.
- **Check the field exists in the data** before using it. A field the stream does not
  carry makes the rule unable to fire; the backtest lists these as missing.
- **Tune on structure, not names.** When a rule fires on benign activity, look for a
  field that separates the benign class from the attack (who served the request, the
  working directory, the parent process) rather than excluding one host or user. It
  fixes the next instance too, and it keeps environment names out of this repository.
- **Re-check the true positives after tuning.** A filter is only done when the known
  attack events (red-team probes, earlier real hits) still match.

## Changing an existing rule

Keep the `id`, bump `modified`, explain the filter in a YAML comment next to it, and
add the benign trigger to `falsepositives`. Put the before/after backtest counts in
the pull request (counts only: samples contain environment data).

## Lifecycle

New rules land as `status: experimental`. Promote to `test` after a clean run
against real data, and to `stable` once the false-positive rate is known.
