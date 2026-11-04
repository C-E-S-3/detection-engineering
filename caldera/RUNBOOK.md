# Purple Team Phase 2 — Caldera runbook

ESKA-445. Profiles and this runbook live in `detection-engineering`. The
launcher lives in `inframan` at `scripts/phase2-caldera-trigger.sh`.

Closed detection-engineering PR #56 is not the procedure. It was never merged.
Use the files on `main` plus this runbook.

Detection validation targets **OpenSearch Sigma** (Security Analytics on
`opensearch.svc.eskridge.internal:9200`). Wazuh is a sensor only. Do not score
this exercise against Wazuh rules, and do not add Wazuh XML when a technique
is `NO RULE`.

## What this exercise is

One Caldera operation runs detection probes for:

| Technique | What the probe does | Sigma tag | Detector / streams |
|---|---|---|---|
| T1190 | HTTP probes (SQLi, traversal, command injection, SSTI, XXE, Nuclei UA, Traefik admin API) against `#{app.web_target}` | `attack.t1190` | traefik / `siem-traefik` |
| T1078 | SSH logins, including an off-hours attempt and `svc_purpleteam` | `attack.t1078` | linux / `siem-linux-auditd` |
| T1055 | ptrace, LD_PRELOAD, `/proc/PID/mem`, memfd_create, process_vm_writev. Syscalls are expected to fail | `attack.t1055` | linux / `siem-linux-auditd`, `siem-linux-sysmon` |
| T1136 | Creates local account `pt_testuser`, then cleans it up. Touches passwd/sudoers paths the ability cleanup reverses | `attack.t1136` | linux / `siem-linux-auditd`, `siem-linux-sysmon` |
| T1003 | Opens `/etc/shadow` and closes it. Does not read or print hashes | `attack.t1003` | linux / `siem-linux-auditd`, `siem-linux-sysmon` |

The validator matches the tag. It does not keep a list of rule ids, so a new
Sigma rule in the right log type is picked up on the next run.

Adversary id: `adv00002-0000-4000-8000-000000000002` (`Phase 2 Purple Team Adversary`).
Agent group: `purple-team-phase2`.

## Where things run

- Caldera server: `http://caldera.svc.eskridge.internal:8888` on secops-monitoring (`10.0.69.4`). The listener is HTTP. `GET /api/v2/health` without the red key returns 401. The stock default key is rejected.
- Red API key: OpenBao `kv/data/caldera/server` field `api_key_red`. Do not copy it into git, issues, or this file.
- OpenSearch: `https://opensearch.svc.eskridge.internal:9200`. Read-only user `sigma_backtest` (role `siem_backtest`), password in OpenBao `kv/data/opensearch` field `sigma_backtest_password`. Do not use `kv/wazuh/indexer` or the break-glass `admin` user.
- Exercise hosts for Sandcat: `beelink-automation`, `nucbox-docker-01`. `protectli-infra-01` is excluded.
- Sandcat playbook (already on inframan `main`): `playbooks/purple-team/caldera-agents.yml`. As of 2026-11-04 there is no Semaphore template for it, and it is not on the Infrastructure Operations Manager allowlist.

## Safety

- Only the exercise hosts and the web target named in the fact source. No external targets.
- Do not change the T1003 ability to `cat` or otherwise print `/etc/shadow`.
- `pt_testuser` is a probe account. The ability cleanup runs `userdel -r`. If an operation is cancelled mid-chain, remove the account by hand on the exercise host.
- T1055 and T1003 are expected to fail at the syscall. A success means the agent context is more privileged than the `sandcat` user and should be treated as a finding, not as a better test.
- T1078 is scored only on `siem-linux-auditd`. The private rule `breakglass_host_ssh_login` (`attack.t1078`) matches `USER_LOGIN` on `hostinger-01` and is not the exercise. Wazuh-shipped auditd still omits `acct` and `addr` on `USER_LOGIN`, so an exercise SSH login can stay `NOT DETECTED` even when the session is real. Do not "fix" that by writing a Wazuh rule. File the gap as a Sigma rule.
- If a probe would hit a host that is not an exercise target, stop.

## One-time setup

1. Sandcat agents checked in and placed in group `purple-team-phase2`. Deploy is `ansible-playbook playbooks/purple-team/caldera-agents.yml` with an OpenBao token that can read `kv/data/caldera/server`. There is no allowlisted Semaphore template for that playbook.
2. Fact source (Caldera UI → Sources, or the API) named `phase2-facts` with traits:
   - `app.web_target` — host:port the agent can reach
   - `host.target` — SSH target
   - `host.target.user` — non-root SSH user
   - `host.ssh.keyfile` — key path on the agent host
   - `host.ssh.svcacct.keyfile` — key for `svc_purpleteam`
3. Note the source UUID. The trigger attaches it only when `CALDERA_SOURCE_ID` is set. Without that, `#{app.web_target}` and the SSH facts do not resolve.

## Launch

Import only (no operation):

```bash
cd inframan
DETECTION_ENG_DIR=/path/to/detection-engineering \
  OPENBAO_TOKEN=... \
  ./scripts/phase2-caldera-trigger.sh --dry-run
```

Full exercise. This creates accounts and runs injection syscalls on the exercise hosts:

```bash
DETECTION_ENG_DIR=/path/to/detection-engineering \
  CALDERA_SOURCE_ID=<phase2-facts-uuid> \
  OPENBAO_TOKEN=... \
  ./scripts/phase2-caldera-trigger.sh --no-cleanup
```

`--no-cleanup` keeps the Caldera operation so the detection query still has a window. It does not skip ability cleanup commands Caldera itself runs.

Equivalent API calls, after the trigger's import (or instead of it), using the red key in `KEY`:

```bash
# agents currently checked in
curl -sS -H "KEY: $CALDERA_API_KEY" \
  "$CALDERA_URL/api/v2/agents"

# start the operation. adversary id is stable.
curl -sS -X POST -H "KEY: $CALDERA_API_KEY" -H "Content-Type: application/json" \
  "$CALDERA_URL/api/v2/operations" \
  -d "{\"name\":\"Phase 2 Purple Team Exercise\",\"adversary\":{\"adversary_id\":\"adv00002-0000-4000-8000-000000000002\"},\"planner\":{\"id\":\"aaa7c857-37a0-4c4a-85f7-4e9f7f30e31a\"},\"group\":\"purple-team-phase2\",\"source\":{\"id\":\"<phase2-facts-uuid>\"},\"obfuscator\":\"plain-text\",\"auto_close\":true,\"state\":\"running\"}"
```

`CALDERA_URL` defaults to `http://caldera.svc.eskridge.internal:8888`.

Poll `GET /api/v2/operations/<id>` until `state` is `finished`, `cleanup`, or `out_of_time`.

## Detection validation

Set `OPENSEARCH_USER` and `OPENSEARCH_PASSWORD` from the `sigma_backtest` identity. The script exits if those are missing, if the user is `admin` or `kibanaserver`, or if the URL points at the Wazuh indexer. It does not try default passwords.

`sigma_backtest` may read findings only if the role allows it. Today `siem_backtest` does not grant the findings API, so the script prints a stderr line and instead runs each deployed rule's compiled query against that technique's `siem-*` streams. A stream hit is a log match for the rule, not proof the detector monitor fired. A later read role with `security_analytics_read_access` uses the findings path with no script change.

```bash
cd detection-engineering
OPENSEARCH_USER=sigma_backtest OPENSEARCH_PASSWORD=... \
  OPENSEARCH_CA=/path/to/homelab-ca.pem \
  python3 caldera/validate-detections.py --since-minutes 180 --fail-on-gaps
```

Optional extra Sigma trees (the private inframan rules, including `attack.t1078`):

```bash
SIGMA_RULES_DIRS=/path/to/inframan/roles/opensearch-security-analytics/files/sigma \
  OPENSEARCH_USER=sigma_backtest OPENSEARCH_PASSWORD=... \
  python3 caldera/validate-detections.py --since-minutes 180
```

The report is one line per technique (`DETECTED`, `NOT DETECTED`, or `NO RULE`) and one line per matching rule with title, id, and timestamp when one was returned. Exit code 1 with `--fail-on-gaps` means at least one technique was not `DETECTED`.

- `DETECTED` — any tagged rule for that detector matched in the window.
- `NOT DETECTED` — a tagged rule exists and nothing matched. File a detection-engineering issue if the ability ran.
- `NO RULE` — nothing in the Sigma trees (or the deployed custom rules) is tagged for that log type. That is Workstream B backlog (ESKA-1080), not a Wazuh rule.

Offline check, no cluster:

```bash
python3 caldera/validate-detections.py --fixture sample.json --fail-on-gaps
```

`sample.json` is either `{"rules": [...], "findings": [...]}` or
`{"rules_search": <rules API body>, "findings_search": <findings API body>}`.

## Add a TTP

1. Add `caldera/abilities/<tactic>/<technique>-<slug>.yml` with a new stable UUID. Command output must not contain secrets or credential material.
2. Append that id to `atomic_ordering` in `caldera/adversaries/phase2-purple-team.yml`.
3. Append the path to `ABILITY_PATHS` in `inframan/scripts/phase2-caldera-trigger.sh`.
4. Add the technique to `TECHNIQUES` in `caldera/validate-detections.py` (tag, log type, streams). Put the Sigma rule in `sigma/<log-type>/` with an `attack.tXXXX` tag. Do not add a Wazuh rule id.
5. Open a PR to each repo. Re-run the trigger with `--dry-run` after both merges before a live operation.

## Cleanup

- Ability cleanup removes `pt_testuser` and reverses the file probes that have a cleanup block. Confirm `id pt_testuser` fails on the exercise host after the operation.
- Delete the Caldera operation when the report is saved, or re-run the trigger without `--no-cleanup`.
- Leave the adversary and abilities in Caldera. Imports are idempotent (stable UUIDs).
- Do not uninstall Sandcat unless the exercise window is over: `ansible-playbook playbooks/purple-team/caldera-agents.yml --tags uninstall`.

## Known limits (2026-11-04)

- This agent cannot read OpenBao, so it cannot import the profile or start the operation from a Paperclip run until a read token for `kv/data/caldera/server` is bound to it. The same is true for `kv/data/opensearch`.
- No Semaphore template runs `caldera-agents.yml`. Template 92 only builds the Caldera server. The Infrastructure Operations Manager allowlist does not include a Sandcat deploy.
- T1190 is covered by the traefik Sigma rules on `siem-traefik` (detection-engineering #134). A `NOT DETECTED` there means those rules did not match the exercise window, not that Traefik logs failed to reach Wazuh.
- T1003 and T1136 have no Sigma rule with `attack.t1003` or `attack.t1136` in detection-engineering as of this writing. The validator reports `NO RULE` until one is added.
- The only `attack.t1078` rule deployed from inframan is `breakglass_host_ssh_login`, scoped to `hostinger-01`. It does not cover the exercise SSH probes. A run that can see deployed rules reports T1078 `NOT DETECTED` rather than `NO RULE`.
