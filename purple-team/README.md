# Purple Team Automation

Caldera-based automation for Phase 2 purple team exercises (ESKA-217).

## Contents

| File | Purpose |
|------|---------|
| `RUNBOOK.md` | Full operational runbook — how to run exercises, validate detections |
| `caldera-setup.py` | One-time setup: creates Caldera abilities and adversary profile via REST API |
| `validate-detections.py` | Post-exercise validation: queries Wazuh Indexer and reports per-TTP coverage |

## Quick Start

```bash
# 1. Setup Caldera (one-time):
python3 caldera-setup.py --openbao

# 2. Launch exercise via API:
curl -sk -X POST -H "KEY: $CALDERA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"Phase 2","adversary":{"adversary_id":"b2170001-e217-4a00-b000-000000000001"},"planner":{"id":"atomic"},"group":"red","state":"running"}' \
  https://caldera.eskridge.internal/api/v2/operations

# 3. Validate detections:
python3 validate-detections.py --openbao --since-minutes 90
```

See [RUNBOOK.md](RUNBOOK.md) for full details.
