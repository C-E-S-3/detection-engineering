# Purple Team Phase 2 — Caldera runbook

ESKA-445. Profiles and this runbook live in `detection-engineering`. The
launcher lives in `inframan` at `scripts/phase2-caldera-trigger.sh`.

Closed detection-engineering PR #56 is not the procedure. It was never merged.
Use the files on `main` plus this runbook.

## What this exercise is

One Caldera operation runs detection probes for:

| Technique | What the probe does | Wazuh rules |
|---|---|---|
| T1190 | HTTP probes (SQLi, traversal, command injection, SSTI, XXE, Nuclei UA, Traefik admin API) against `#{app.web_target}` | 100820–100829 |
| T1078 | SSH logins, including an off-hours attempt and `svc_purpleteam` | 100840–100849 |
| T1055 | ptrace, LD_PRELOAD, `/proc/PID/mem`, memfd_create, process_vm_writev. Syscalls are expected to fail | 100830–100839 |
| T1136 | Creates local account `pt_testuser`, then cleans it up. Touches passwd/sudoers paths the ability cleanup reverses | 100850–100859 |
| T1003 | Opens `/etc/shadow` and closes it. Does not read or print hashes | 100775 (phase 1) |

Adversary id: `adv00002-0000-4000-8000-000000000002` (`Phase 2 Purple Team Adversary`).
Agent group: `purple-team-phase2`.

## Where things run

- Caldera server: `http://caldera.svc.eskridge.internal:8888` on secops-monitoring (`10.0.69.4`). The listener is HTTP. `GET /api/v2/health` without the red key returns 401. The stock default key is rejected.
- Red API key: OpenBao `kv/data/caldera/server` field `api_key_red`. Do not copy it into git, issues, or this file.
- Exercise hosts for Sandcat: `beelink-automation`, `nucbox-docker-01`. `protectli-infra-01` is excluded.
- Sandcat playbook (already on inframan `main`): `playbooks/purple-team/caldera-agents.yml`. As of 2026-11-04 there is no Semaphore template for it, and it is not on the Infrastructure Operations Manager allowlist.

## Safety

- Only the exercise hosts and the web target named in the fact source. No external targets.
- Do not change the T1003 ability to `cat` or otherwise print `/etc/shadow`.
- `pt_testuser` is a probe account. The ability cleanup runs `userdel -r`. If an operation is cancelled mid-chain, remove the account by hand on the exercise host.
- T1055 and T1003 are expected to fail at the syscall. A success means the agent context is more privileged than the `sandcat` user and should be treated as a finding, not as a better test.
- Off-hours rule 100842 only matches 00:00–07:00 on the Wazuh manager clock. A daytime run can still pass T1078 via 100840 or 100844.
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

`--no-cleanup` keeps the Caldera operation so the Wazuh query still has a window. It does not skip ability cleanup commands Caldera itself runs.

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

Indexer credentials are OpenBao `kv/wazuh/indexer` (`WAZUH_INDEXER_USERNAME` / `WAZUH_INDEXER_PASSWORD`). Do not use the default-password loop that exists in `phase2-caldera-execute.yml`.

```bash
cd detection-engineering
WAZUH_INDEXER_USERNAME=... WAZUH_INDEXER_PASSWORD=... \
  python3 caldera/validate-detections.py --since-minutes 180 --fail-on-gaps
```

The report is one line per technique (`DETECTED` / `NOT DETECTED` plus alert count) and one line per rule with level and timestamp when the indexer returned them. Exit code 1 with `--fail-on-gaps` means at least one technique had zero alerts.

A technique is `DETECTED` if any rule in its set fired. Individual rules that stay `NOT DETECTED` are still gaps: file a detection-engineering issue per rule that the matching ability ran and the rule did not fire.

The Ansible tag `wazuh-check` on `playbooks/purple-team/phase2-caldera-execute.yml` is the older on-host check. It queries the manager API on secops-monitoring and does not include rule 100775. Prefer `validate-detections.py` for the per-TTP report.

## Add a TTP

1. Add `caldera/abilities/<tactic>/<technique>-<slug>.yml` with a new stable UUID. Command output must not contain secrets or credential material.
2. Append that id to `atomic_ordering` in `caldera/adversaries/phase2-purple-team.yml`.
3. Append the path to `ABILITY_PATHS` in `inframan/scripts/phase2-caldera-trigger.sh`.
4. Add the rule id and label to `RULES` in `caldera/validate-detections.py`.
5. Open a PR to each repo. Re-run the trigger with `--dry-run` after both merges before a live operation.

## Cleanup

- Ability cleanup removes `pt_testuser` and reverses the file probes that have a cleanup block. Confirm `id pt_testuser` fails on the exercise host after the operation.
- Delete the Caldera operation when the report is saved, or re-run the trigger without `--no-cleanup`.
- Leave the adversary and abilities in Caldera. Imports are idempotent (stable UUIDs).
- Do not uninstall Sandcat unless the exercise window is over: `ansible-playbook playbooks/purple-team/caldera-agents.yml --tags uninstall`.

## Known limits (2026-11-04)

- This agent cannot read OpenBao, so it cannot import the profile or start the operation from a Paperclip run until a read token for `kv/data/caldera/server` is bound to it.
- No Semaphore template runs `caldera-agents.yml` or `phase2-caldera-execute.yml`. Template 92 only builds the Caldera server. The Infrastructure Operations Manager allowlist does not include a Sandcat deploy.
- T1190 alerts depend on Traefik access logs reaching Wazuh. A prior finding (ESKA-1091) was that those logs were not arriving, so a clean Caldera run can still show T1190 `NOT DETECTED`.
