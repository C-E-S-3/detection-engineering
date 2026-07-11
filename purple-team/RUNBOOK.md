# Purple Team Phase 2 — Caldera Exercise Runbook

ESKA-445 · ESKA-217 (Purple Team Phase 2)

## Overview

This runbook covers the Caldera-automated version of the Phase 2 purple team exercise.
Caldera replaces the Semaphore-operator dependency: once Sandcat agents are deployed to target hosts,
exercises can be launched via the Caldera API without a human triggering Semaphore templates.

## Architecture

```
Operator → Caldera REST API → Caldera Server (secops-monitoring)
                                      ↓
                              Sandcat C2 agents (beelink-automation, nucbox-docker-01, protectli-infra-01)
                                      ↓
                              Target host actions (T1190/T1055/T1078/T1136/T1003)
                                      ↓
                              Wazuh Agent → Wazuh Manager → Wazuh Indexer
                                      ↓
                              validate-detections.py → DETECTED/NOT DETECTED report
```

## Prerequisites

| Component | Status | Notes |
|-----------|--------|-------|
| Caldera server | Requires ESKA-443 deploy | `https://caldera.eskridge.internal` |
| Sandcat agents | Requires ESKA-444 deploy | 3 hosts registered |
| Wazuh rules deployed | DONE (ESKA-431) | Rules 100820–100859 on main |
| Caldera abilities configured | Run `caldera-setup.py` | See Setup below |

## Setup (one-time)

### 1. Configure Caldera abilities and adversary profile

```bash
# Fetch Caldera API key from OpenBao:
export VAULT_ADDR=https://openbao.eskridge.internal
vault login -method=oidc

cd purple-team/
python3 caldera-setup.py --openbao
```

Or with explicit API key:
```bash
CALDERA_API_KEY=$(vault kv get -field=api_key caldera/server) \
  python3 caldera-setup.py
```

Dry-run to see what would be created:
```bash
python3 caldera-setup.py --dry-run
```

### 2. Verify Sandcat agents are registered

```bash
CALDERA_API_KEY=<key> curl -sk -H "KEY: $CALDERA_API_KEY" \
  https://caldera.eskridge.internal/api/v2/agents | python3 -m json.tool
```

Expected: 3 agents (beelink-automation, nucbox-docker-01, protectli-infra-01).

## Running an Exercise

### Option A: Caldera UI

1. Browse to `https://caldera.eskridge.internal`
2. Login with admin credentials (from OpenBao: `caldera/server` → `admin_password`)
3. Navigate to **Operations** → **New Operation**
4. Select adversary: **Purple Team Phase 2**
5. Select group: **red** (all Sandcat agents)
6. Set planner: **Atomic**
7. Click **Start**

### Option B: Caldera REST API (recommended for automation)

```bash
CALDERA_API_KEY=$(vault kv get -field=api_key caldera/server)

curl -sk -X POST \
  -H "KEY: $CALDERA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Phase 2 Exercise '$(date +%Y%m%d-%H%M)'",
    "adversary": {"adversary_id": "b2170001-e217-4a00-b000-000000000001"},
    "planner": {"id": "atomic"},
    "group": "red",
    "state": "running",
    "obfuscator": "plain-text",
    "autonomous": 1
  }' \
  https://caldera.eskridge.internal/api/v2/operations \
  | python3 -m json.tool
```

Save the returned `id` for monitoring.

### Monitor operation progress

```bash
OP_ID=<uuid-from-above>
curl -sk -H "KEY: $CALDERA_API_KEY" \
  https://caldera.eskridge.internal/api/v2/operations/$OP_ID \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['state'], d.get('finish','running'))"
```

States: `running` → `cleanup` → `finished`

### Run a specific TTP only (using ability ID directly)

```bash
# T1055 ptrace only:
curl -sk -X POST \
  -H "KEY: $CALDERA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "T1055 ptrace test",
    "adversary": {
      "adversary_id": "custom",
      "atomic_ordering": ["a1055001-e217-4a00-b000-000000000001"]
    },
    "planner": {"id": "atomic"},
    "group": "red",
    "state": "running"
  }' \
  https://caldera.eskridge.internal/api/v2/operations
```

## Validating Detections

### After operation completes

```bash
export WAZUH_INDEXER_USERNAME=$(vault kv get -field=username wazuh/indexer)
export WAZUH_INDEXER_PASSWORD=$(vault kv get -field=password wazuh/indexer)

python3 validate-detections.py --since-minutes 90
```

### Watch Caldera operation + auto-validate when done

```bash
python3 validate-detections.py \
  --openbao \
  --caldera-operation-id $OP_ID \
  --caldera-api-key $CALDERA_API_KEY \
  --watch
```

### JSON output (for automated reporting)

```bash
python3 validate-detections.py --openbao --json > exercise-report-$(date +%Y%m%d).json
```

### Exit 1 on coverage gaps (CI integration)

```bash
python3 validate-detections.py --openbao --fail-on-gaps
echo $?  # 0 = full coverage, 1 = gaps found
```

## Expected Detection Coverage

| TTP | Rules | Key Triggers |
|-----|-------|-------------|
| T1190 | 100820–100829 | Nuclei UA, SQLi, path traversal, cmd injection, API enum in Traefik access logs |
| T1055 | 100830–100839 | ptrace(PTRACE_ATTACH) syscall via auditd, LD_PRELOAD, /proc/pid/mem open |
| T1078 | 100840–100849 | Root SSH login, multi-user same IP, off-hours auth, service account SSH |
| T1136 | 100850–100859 | useradd, sudoers drop-in, usermod group change, /etc/passwd FIM alert |

## Adding New TTPs

### 1. Write the Caldera ability

In `caldera-setup.py`, add a new entry to `ABILITIES`:

```python
{
    "ability_id": "aXXXXXXX-e217-4a00-b000-000000000001",  # stable UUID
    "tactic": "lateral-movement",
    "technique_id": "T1021",
    "technique_name": "Remote Services",
    "name": "T1021 — SSH lateral movement",
    "description": "...",
    "executors": [make_executor(
        "ssh -o StrictHostKeyChecking=no #{caldera_target} 'id' 2>&1",
    )],
}
```

Add the ability_id to `ADVERSARY["atomic_ordering"]` (or create a new adversary).

### 2. Write the Wazuh detection rule

Follow [detection-engineering/wazuh/rules/](../wazuh/rules/) conventions.
Submit a PR to `C-E-S-3/detection-engineering`.

### 3. Add rule to validate-detections.py

Add to `PHASE2_RULES` dict:
```python
"XXXXXX": ("T1021", "SSH lateral movement"),
```

### 4. Re-run setup and test

```bash
python3 caldera-setup.py  # re-upserts, idempotent
python3 validate-detections.py --since-minutes 30
```

## Caldera Ability UUIDs

| TTP | Ability | UUID |
|-----|---------|------|
| T1190 | Nuclei scan | `a1900001-e217-4a00-b000-000000000001` |
| T1190 | SQLi probe | `a1900001-e217-4a00-b000-000000000002` |
| T1190 | Path traversal | `a1900001-e217-4a00-b000-000000000003` |
| T1190 | Cmd injection | `a1900001-e217-4a00-b000-000000000004` |
| T1190 | API enum | `a1900001-e217-4a00-b000-000000000005` |
| T1055 | ptrace ATTACH | `a1055001-e217-4a00-b000-000000000001` |
| T1055 | LD_PRELOAD | `a1055001-e217-4a00-b000-000000000002` |
| T1055 | /proc/pid/mem | `a1055001-e217-4a00-b000-000000000003` |
| T1078 | Root SSH log | `a1078001-e217-4a00-b000-000000000001` |
| T1078 | Cred stuffing | `a1078001-e217-4a00-b000-000000000002` |
| T1136 | useradd | `a1136001-e217-4a00-b000-000000000001` |
| T1136 | sudoers | `a1136001-e217-4a00-b000-000000000002` |
| T1136 | cleanup | `a1136001-e217-4a00-b000-000000000003` |
| T1003 | Shadow read | `a1003001-e217-4a00-b000-000000000001` |
| Adversary | Purple Team Phase 2 | `b2170001-e217-4a00-b000-000000000001` |

## Safety Procedures

**Authorized scope only:**
- beelink-automation (10.4.55.11) — internal infra_vms
- nucbox-docker-01 (10.0.69.x) — internal infra_vms
- protectli-infra-01 (172.16.4.28) — DMZ, T1190 target only

**Never:**
- Run against external IP addresses
- Use real credentials in ability commands
- Exfiltrate real data (all test data is synthetic/dummy)
- Run without CISO-authorized exercise window (see ESKA-217)

**If a test causes unexpected service impact:**
1. Stop the Caldera operation immediately:
   ```bash
   curl -sk -X PATCH -H "KEY: $CALDERA_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{"state": "stop"}' \
     https://caldera.eskridge.internal/api/v2/operations/$OP_ID
   ```
2. Run the T1136 cleanup ability to remove any test users:
   ```bash
   # Trigger cleanup ability a1136001-e217-4a00-b000-000000000003
   ```
3. Notify Security Operations Manager immediately

## Cleanup After Exercise

Caldera abilities include cleanup commands that run automatically.
For manual cleanup if needed:

```bash
# Remove test user on beelink-automation
ansible beelink-automation -m command -a "userdel -rf pt-backdoor-test" --become

# Remove sudoers drop-in
ansible beelink-automation -m file -a "path=/etc/sudoers.d/99-pt-test-REMOVE state=absent" --become

# Verify no test artifacts remain
ansible caldera_exercise_hosts -m command -a "id pt-backdoor-test" --become
# Expected: all return non-zero (user not found)
```

## References

- [ESKA-217](/ESKA/issues/ESKA-217) — Purple Team Phase 2 Exercise
- [ESKA-442](/ESKA/issues/ESKA-442) — Caldera platform implementation
- [ESKA-443](/ESKA/issues/ESKA-443) — Caldera server build (ansible-builder PR #51)
- [ESKA-444](/ESKA/issues/ESKA-444) — Sandcat agent deployment (inframan PR #139)
- [ESKA-445](/ESKA/issues/ESKA-445) — This configuration
- [Caldera REST API docs](https://caldera.readthedocs.io/en/latest/REST-API.html)
- [inframan: purple-team-phase2-art.yml](https://github.com/C-E-S-3/inframan/blob/main/purple-team-phase2-art.yml) — Ansible fallback for same exercise
