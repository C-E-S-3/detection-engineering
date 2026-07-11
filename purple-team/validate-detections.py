#!/usr/bin/env python3
"""
validate-detections.py — Phase 2 purple team detection validation

Queries the Wazuh Indexer (OpenSearch) for Phase 2 exercise alerts and
produces a per-TTP DETECTED / NOT DETECTED report.

Usage:
  # Credentials from env (set by Semaphore or manually):
  WAZUH_INDEXER_USERNAME=admin WAZUH_INDEXER_PASSWORD=<pw> python3 validate-detections.py

  # Look back N minutes (default: 60):
  python3 validate-detections.py --since-minutes 30

  # OpenBao for credentials:
  python3 validate-detections.py --openbao

  # Watch a running Caldera operation (poll every 30s until complete):
  python3 validate-detections.py --caldera-operation-id <uuid> --watch

  # JSON output:
  python3 validate-detections.py --json

ESKA-445
"""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Optional

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("ERROR: 'requests' not installed. Run: pip3 install requests", file=sys.stderr)
    sys.exit(1)

WAZUH_INDEXER_URL = os.environ.get("WAZUH_INDEXER_URL", "https://wazuh.svc.eskridge.internal:9200")
CALDERA_URL = os.environ.get("CALDERA_URL", "https://caldera.eskridge.internal")

# Phase 2 rule IDs and their labels (matches purple-team-phase2-art.yml)
PHASE2_RULES = {
    # T1190 — Exploit Public-Facing Application
    "100820": ("T1190", "Traefik API enum"),
    "100821": ("T1190", "Traefik API rawdata"),
    "100822": ("T1190", "SQLi pattern"),
    "100823": ("T1190", "Path traversal"),
    "100824": ("T1190", "Command injection"),
    "100825": ("T1190", "Traefik API routers/services"),
    "100826": ("T1190", "Traefik API entrypoints"),
    "100827": ("T1190", "Traefik API version"),
    "100828": ("T1190", "Traefik API overview"),
    "100829": ("T1190", "Nuclei scanner UA"),
    # T1055 — Process Injection
    "100830": ("T1055", "ptrace ATTACH"),
    "100831": ("T1055", "ptrace syscall (auditd)"),
    "100833": ("T1055", "LD_PRELOAD set"),
    "100834": ("T1055", "/proc/pid/mem access"),
    "100835": ("T1055", "Suspicious .so in /tmp"),
    "100836": ("T1055", "ptrace DETACH"),
    "100837": ("T1055", "PTRACE_POKETEXT"),
    "100838": ("T1055", "process_vm_writev"),
    "100839": ("T1055", "memfd_create"),
    # T1078 — Valid Accounts
    "100840": ("T1078", "SSH login no prior failure"),
    "100841": ("T1078", "SSH password auth"),
    "100842": ("T1078", "Off-hours SSH login"),
    "100844": ("T1078", "Service account SSH"),
    "100845": ("T1078", "SSH from new source"),
    "100846": ("T1078", "Root SSH login"),
    "100847": ("T1078", "Multi-user same IP"),
    # T1136 — Create Account
    "100850": ("T1136", "useradd"),
    "100852": ("T1136", "adduser"),
    "100854": ("T1136", "sudoers modification"),
    "100855": ("T1136", "usermod group change"),
    "100856": ("T1136", "sudo group add"),
    "100858": ("T1136", "/etc/passwd FIM"),
}

TTP_ORDER = ["T1190", "T1055", "T1078", "T1136"]
TTP_LABELS = {
    "T1190": "Exploit Public-Facing Application (protectli-infra-01)",
    "T1055": "Process Injection (beelink-automation)",
    "T1078": "Valid Accounts (beelink-automation)",
    "T1136": "Create Account (beelink-automation)",
}


def get_credentials(use_openbao: bool) -> tuple[str, str]:
    if use_openbao:
        try:
            user = subprocess.run(
                ["vault", "kv", "get", "-field=username", "wazuh/indexer"],
                capture_output=True, text=True, timeout=15, check=True,
            ).stdout.strip()
            pw = subprocess.run(
                ["vault", "kv", "get", "-field=password", "wazuh/indexer"],
                capture_output=True, text=True, timeout=15, check=True,
            ).stdout.strip()
            return user, pw
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"ERROR: OpenBao lookup failed: {e}", file=sys.stderr)
            sys.exit(1)

    user = os.environ.get("WAZUH_INDEXER_USERNAME", "")
    pw = os.environ.get("WAZUH_INDEXER_PASSWORD", "")
    if not user or not pw:
        print(
            "ERROR: WAZUH_INDEXER_USERNAME/WAZUH_INDEXER_PASSWORD not set.\n"
            "  Use --openbao or export credentials directly.",
            file=sys.stderr,
        )
        sys.exit(1)
    return user, pw


def query_wazuh(
    indexer_url: str,
    username: str,
    password: str,
    rule_ids: list[str],
    since_minutes: int = 60,
    start_time: Optional[str] = None,
) -> dict[str, int]:
    """Return {rule_id: alert_count} for the given rule IDs and time window."""

    if start_time:
        time_filter = {"gte": start_time}
    else:
        time_filter = {"gte": f"now-{since_minutes}m"}

    body = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"terms": {"rule.id": rule_ids}},
                    {"range": {"@timestamp": time_filter}},
                ]
            }
        },
        "aggs": {
            "by_rule_id": {
                "terms": {"field": "rule.id", "size": 200}
            }
        },
    }

    url = f"{indexer_url.rstrip('/')}/wazuh-alerts-*/_search"
    resp = requests.post(
        url,
        json=body,
        auth=(username, password),
        verify=False,
        timeout=20,
    )
    resp.raise_for_status()

    data = resp.json()
    counts: dict[str, int] = {}
    for bucket in data.get("aggregations", {}).get("by_rule_id", {}).get("buckets", []):
        counts[str(bucket["key"])] = bucket["doc_count"]
    return counts


def wait_for_caldera_operation(caldera_url: str, api_key: str, op_id: str) -> bool:
    """Poll until operation is complete. Return True if finished, False on timeout."""
    url = f"{caldera_url.rstrip('/')}/api/v2/operations/{op_id}"
    headers = {"KEY": api_key, "Content-Type": "application/json"}

    for attempt in range(60):  # max 30 min
        resp = requests.get(url, headers=headers, verify=False, timeout=15)
        if resp.status_code == 200:
            state = resp.json().get("state", "unknown")
            print(f"  Operation state: {state}", end="\r")
            if state in ("finished", "cleanup", "out_of_time"):
                print()
                return True
        time.sleep(30)

    print()
    return False


def build_report(counts: dict[str, int]) -> dict:
    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_detected": 0,
        "total_rules": len(PHASE2_RULES),
        "by_ttp": {},
        "by_rule": {},
    }

    for ttp in TTP_ORDER:
        report["by_ttp"][ttp] = {"label": TTP_LABELS[ttp], "detected": 0, "total": 0}

    for rule_id, (ttp, label) in PHASE2_RULES.items():
        count = counts.get(rule_id, 0)
        detected = count > 0
        report["by_rule"][rule_id] = {
            "ttp": ttp,
            "label": label,
            "detected": detected,
            "alert_count": count,
        }
        report["by_ttp"][ttp]["total"] += 1
        if detected:
            report["by_ttp"][ttp]["detected"] += 1
            report["total_detected"] += 1

    return report


def print_report(report: dict):
    ts = report["timestamp"]
    total = report["total_detected"]
    rules = report["total_rules"]
    pct = int(total / rules * 100) if rules else 0

    print()
    print("=" * 65)
    print(f"  PHASE 2 PURPLE TEAM EXERCISE — DETECTION REPORT")
    print(f"  {ts}")
    print("=" * 65)
    print(f"  Coverage: {total}/{rules} rules fired ({pct}%)")
    print("=" * 65)

    for ttp in TTP_ORDER:
        ttp_data = report["by_ttp"][ttp]
        ttp_pct = int(ttp_data["detected"] / ttp_data["total"] * 100) if ttp_data["total"] else 0
        print(f"\n  {ttp} — {ttp_data['label']}")
        print(f"  Coverage: {ttp_data['detected']}/{ttp_data['total']} ({ttp_pct}%)")

        for rule_id, rule_data in report["by_rule"].items():
            if rule_data["ttp"] != ttp:
                continue
            status = f"DETECTED ({rule_data['alert_count']})" if rule_data["detected"] else "NOT DETECTED"
            marker = "✓" if rule_data["detected"] else "✗"
            print(f"    {marker} Rule {rule_id} ({rule_data['label']}): {status}")

    print()
    print("=" * 65)
    if total == rules:
        print("  RESULT: ALL RULES FIRED — Full detection coverage confirmed")
    elif total >= rules * 0.8:
        print(f"  RESULT: PARTIAL COVERAGE — {rules - total} rules NOT fired (review gaps)")
    else:
        print(f"  RESULT: COVERAGE GAPS — {rules - total} rules NOT fired (action required)")
    print("=" * 65)
    print()


def main():
    parser = argparse.ArgumentParser(description="Validate Phase 2 purple team detections in Wazuh")
    parser.add_argument("--openbao", action="store_true", help="Fetch Wazuh credentials from OpenBao")
    parser.add_argument("--since-minutes", type=int, default=60, help="Look back N minutes (default: 60)")
    parser.add_argument("--start-time", help="ISO8601 start time (e.g. 2026-07-11T20:00:00Z)")
    parser.add_argument("--indexer-url", default=WAZUH_INDEXER_URL, help=f"Wazuh Indexer URL (default: {WAZUH_INDEXER_URL})")
    parser.add_argument("--caldera-operation-id", help="Poll this Caldera operation ID before querying")
    parser.add_argument("--caldera-api-key", help="Caldera API key (for --caldera-operation-id)")
    parser.add_argument("--caldera-url", default=CALDERA_URL, help=f"Caldera URL (default: {CALDERA_URL})")
    parser.add_argument("--watch", action="store_true", help="Poll Caldera op until finished, then validate")
    parser.add_argument("--json", action="store_true", dest="json_output", help="Output report as JSON")
    parser.add_argument("--fail-on-gaps", action="store_true", help="Exit 1 if any rules did not fire")
    args = parser.parse_args()

    username, password = get_credentials(args.openbao)

    if args.caldera_operation_id and args.watch:
        caldera_key = args.caldera_api_key or os.environ.get("CALDERA_API_KEY", "")
        if not caldera_key:
            print("ERROR: --caldera-api-key or CALDERA_API_KEY required with --watch", file=sys.stderr)
            sys.exit(1)
        print(f"Waiting for Caldera operation {args.caldera_operation_id} to complete...")
        done = wait_for_caldera_operation(args.caldera_url, caldera_key, args.caldera_operation_id)
        if not done:
            print("WARNING: Operation did not complete within 30 minutes — validating anyway")
        print("Querying Wazuh Indexer for detections...")
    else:
        print("Querying Wazuh Indexer for detections...")

    rule_ids = list(PHASE2_RULES.keys())
    try:
        counts = query_wazuh(
            args.indexer_url,
            username,
            password,
            rule_ids,
            since_minutes=args.since_minutes,
            start_time=args.start_time,
        )
    except Exception as e:
        print(f"ERROR: Wazuh Indexer query failed: {e}", file=sys.stderr)
        print("Check WAZUH_INDEXER_URL and credentials. Self-signed cert is expected (verify=False).", file=sys.stderr)
        sys.exit(2)

    report = build_report(counts)

    if args.json_output:
        print(json.dumps(report, indent=2))
    else:
        print_report(report)

    if args.fail_on_gaps and report["total_detected"] < report["total_rules"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
