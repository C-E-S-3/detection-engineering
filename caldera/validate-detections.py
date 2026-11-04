#!/usr/bin/env python3
"""Per-TTP Wazuh detection report for the Phase 2 purple-team exercise.

Queries the Wazuh indexer (OpenSearch) for rules 100820-100859 and phase-1
rule 100775, then prints DETECTED / NOT DETECTED with rule id, level, and
latest timestamp.

Credentials come from the environment. This script does not embed passwords
and does not try default accounts.

  WAZUH_INDEXER_USERNAME=... WAZUH_INDEXER_PASSWORD=... \
    python3 caldera/validate-detections.py --since-minutes 180

  python3 caldera/validate-detections.py --fixture sample.json --fail-on-gaps

ESKA-445
"""

from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from collections import OrderedDict

INDEXER_URL = os.environ.get(
    "WAZUH_INDEXER_URL", "https://wazuh.svc.eskridge.internal:9200"
).rstrip("/")

# technique -> ordered (rule_id, short label)
RULES = OrderedDict(
    [
        (
            "T1190",
            [
                ("100820", "Traefik admin API access"),
                ("100821", "Traefik admin API 200"),
                ("100822", "SQL injection pattern"),
                ("100823", "Path traversal"),
                ("100824", "Command injection"),
                ("100825", "Traefik API enumeration burst"),
                ("100826", "Traefik HTTP 5xx"),
                ("100827", "SSTI pattern"),
                ("100828", "XXE pattern"),
                ("100829", "Scanner user-agent"),
            ],
        ),
        (
            "T1055",
            [
                ("100830", "ptrace PTRACE_ATTACH"),
                ("100831", "ptrace by non-debugger"),
                ("100832", "ptrace PEEK/POKE"),
                ("100833", "LD_PRELOAD suspicious path"),
                ("100834", "/proc/PID/mem write"),
                ("100835", "library from world-writable path"),
                ("100836", "/etc/ld.so.preload write"),
                ("100837", "memfd_create"),
                ("100838", "process_vm_writev"),
                ("100839", "ptrace plus /proc/mem sequence"),
            ],
        ),
        (
            "T1078",
            [
                ("100840", "SSH login"),
                ("100841", "auth from known-bad IP"),
                ("100842", "off-hours login"),
                ("100843", "weekend login"),
                ("100844", "service-account interactive SSH"),
                ("100845", "auth after brute force"),
                ("100846", "direct root SSH"),
                ("100847", "multiple auths same source"),
                ("100848", "locked or expired account"),
                ("100849", "off-hours su/sudo"),
            ],
        ),
        (
            "T1136",
            [
                ("100850", "useradd"),
                ("100851", "useradd by non-root"),
                ("100852", "FIM /etc/passwd"),
                ("100853", "FIM /etc/shadow modified"),
                ("100854", "FIM sudoers"),
                ("100855", "FIM /etc/group"),
                ("100856", "usermod/groupmod"),
                ("100857", "non-root /etc/passwd write"),
                ("100858", "PAM useradd"),
                ("100859", "new account then SSH"),
            ],
        ),
        (
            "T1003",
            [
                ("100775", "non-root open of /etc/shadow"),
            ],
        ),
    ]
)

TTP_NAMES = {
    "T1190": "Exploit Public-Facing Application",
    "T1055": "Process Injection",
    "T1078": "Valid Accounts",
    "T1136": "Create Account",
    "T1003": "OS Credential Dumping",
}


def all_rule_ids():
    ids = []
    for rows in RULES.values():
        ids.extend(int(rule_id) for rule_id, _label in rows)
    return ids


def build_query(since_minutes: int) -> dict:
    return {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"terms": {"rule.id": all_rule_ids()}},
                    {"range": {"@timestamp": {"gte": "now-%dm" % since_minutes}}},
                ]
            }
        },
        "aggs": {
            "by_rule_id": {
                "terms": {"field": "rule.id", "size": 80},
                "aggs": {
                    "newest": {
                        "top_hits": {
                            "size": 1,
                            "sort": [{"@timestamp": "desc"}],
                            "_source": ["@timestamp", "rule.level", "rule.id", "agent.name"],
                        }
                    }
                },
            }
        },
    }


def indexer_search(body: dict) -> dict:
    user = os.environ.get("WAZUH_INDEXER_USERNAME", "")
    password = os.environ.get("WAZUH_INDEXER_PASSWORD", "")
    if not user or not password:
        sys.exit(
            "WAZUH_INDEXER_USERNAME and WAZUH_INDEXER_PASSWORD are required "
            "(kv/wazuh/indexer). Refusing to try default credentials."
        )
    url = INDEXER_URL + "/wazuh-alerts-*/_search"
    data = json.dumps(body).encode()
    password_mgr = urllib.request.HTTPPasswordMgrWithPriorAuth()
    password_mgr.add_password(None, url, user, password, is_authenticated=True)
    handlers = [
        urllib.request.HTTPBasicAuthHandler(password_mgr),
        urllib.request.HTTPSHandler(context=ssl._create_unverified_context()),
    ]
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with opener.open(req, timeout=20) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")[:500]
        # top_hits on a missing field should not hide the count query
        if exc.code == 400 and "newest" in body.get("aggs", {}).get("by_rule_id", {}).get("aggs", {}):
            fallback = json.loads(json.dumps(body))
            del fallback["aggs"]["by_rule_id"]["aggs"]
            return indexer_search(fallback)
        sys.exit("indexer HTTP %s: %s" % (exc.code, detail))
    except urllib.error.URLError as exc:
        sys.exit("indexer unreachable: %s" % exc.reason)


def buckets_from(payload: dict) -> dict:
    found = {}
    aggs = payload.get("aggregations") or {}
    buckets = (aggs.get("by_rule_id") or {}).get("buckets") or []
    for bucket in buckets:
        rule_id = str(bucket.get("key"))
        evidence = {"count": int(bucket.get("doc_count") or 0), "level": None, "timestamp": None, "agent": None}
        hits = (((bucket.get("newest") or {}).get("hits") or {}).get("hits")) or []
        if hits:
            source = hits[0].get("_source") or {}
            evidence["timestamp"] = source.get("@timestamp")
            rule = source.get("rule") or {}
            evidence["level"] = rule.get("level")
            agent = source.get("agent") or {}
            evidence["agent"] = agent.get("name")
        found[rule_id] = evidence
    return found


def build_report(found: dict) -> dict:
    ttps = []
    for technique, rows in RULES.items():
        rules = []
        total = 0
        for rule_id, label in rows:
            evidence = found.get(rule_id) or {"count": 0, "level": None, "timestamp": None, "agent": None}
            total += evidence["count"]
            rules.append(
                {
                    "rule_id": rule_id,
                    "label": label,
                    "status": "DETECTED" if evidence["count"] else "NOT DETECTED",
                    "count": evidence["count"],
                    "level": evidence["level"],
                    "timestamp": evidence["timestamp"],
                    "agent": evidence["agent"],
                }
            )
        ttps.append(
            {
                "technique": technique,
                "name": TTP_NAMES[technique],
                "status": "DETECTED" if total else "NOT DETECTED",
                "count": total,
                "rules": rules,
            }
        )
    return {"ttps": ttps}


def render_text(report: dict) -> str:
    lines = ["Phase 2 purple team — Wazuh detection report", ""]
    for ttp in report["ttps"]:
        lines.append(
            "%s %s: %s (%d alerts)"
            % (ttp["technique"], ttp["name"], ttp["status"], ttp["count"])
        )
        for rule in ttp["rules"]:
            extra = ""
            if rule["status"] == "DETECTED":
                bits = []
                if rule["level"] is not None:
                    bits.append("level=%s" % rule["level"])
                if rule["timestamp"]:
                    bits.append("timestamp=%s" % rule["timestamp"])
                if rule["agent"]:
                    bits.append("agent=%s" % rule["agent"])
                if bits:
                    extra = " " + " ".join(bits)
            lines.append(
                "  %s %s (%d) %s%s"
                % (rule["rule_id"], rule["status"], rule["count"], rule["label"], extra)
            )
        lines.append("")
    missing = [t["technique"] for t in report["ttps"] if t["status"] != "DETECTED"]
    if missing:
        lines.append("Gaps: " + ", ".join(missing))
    else:
        lines.append("Gaps: none")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--since-minutes", type=int, default=180)
    parser.add_argument("--fixture", help="Indexer JSON response. Skips the network.")
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument("--fail-on-gaps", action="store_true")
    args = parser.parse_args()
    if args.since_minutes < 1:
        sys.exit("--since-minutes must be >= 1")

    if args.fixture:
        with open(args.fixture, encoding="utf-8") as handle:
            payload = json.load(handle)
    else:
        payload = indexer_search(build_query(args.since_minutes))

    report = build_report(buckets_from(payload))
    if args.as_json:
        print(json.dumps(report, indent=2))
    else:
        print(render_text(report))
    if args.fail_on_gaps and any(t["status"] != "DETECTED" for t in report["ttps"]):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
