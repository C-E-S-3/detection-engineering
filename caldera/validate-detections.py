#!/usr/bin/env python3
"""Per-TTP OpenSearch Sigma report for the Phase 2 purple-team exercise.

Scores T1190, T1055, T1078, T1136, and T1003 from Security Analytics, not from
Wazuh rule ids. A technique is:

  DETECTED      a finding (or, if the findings API is forbidden, a siem-* hit
                on a deployed Sigma query) in the window, with rule title, id,
                and timestamp
  NOT DETECTED  a Sigma rule tagged attack.tXXXX exists for that detector, and
                nothing matched in the window
  NO RULE       no Sigma rule carries that tag for the technique's log type

NO RULE is a detection-engineering gap (Workstream B, ESKA-1080). It is not a
prompt to write a Wazuh XML rule.

Credentials are OPENSEARCH_USER / OPENSEARCH_PASSWORD for a read-only identity.
The homelab user is sigma_backtest (OpenBao kv/data/opensearch, field
sigma_backtest_password). Its role can search siem-* and read Security
Analytics rules, and cannot read findings indices, so a 403 on the findings
API falls back to those streams. Do not use kv/wazuh/indexer, the break-glass
admin user, or any default password.

  OPENSEARCH_USER=sigma_backtest OPENSEARCH_PASSWORD=... \\
    python3 caldera/validate-detections.py --since-minutes 180 --fail-on-gaps

  python3 caldera/validate-detections.py --fixture sample.json --fail-on-gaps

ESKA-445
"""

from __future__ import annotations

import argparse
import base64
import datetime
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

DEFAULT_URL = "https://opensearch.svc.eskridge.internal:9200"
DENIED_USERS = {"admin", "kibanaserver", "kibanaro", "logstash", "anomalyadmin"}
DENIED_PASSWORDS = {"admin", "admin123", "adminpassword", "changeme"}

# technique, ATT&CK tag, Security Analytics log type, data streams
TECHNIQUES = (
    {
        "technique": "T1190",
        "name": "Exploit Public-Facing Application",
        "tag": "attack.t1190",
        "log_types": ("traefik",),
        "streams": ("siem-traefik",),
    },
    {
        "technique": "T1055",
        "name": "Process Injection",
        "tag": "attack.t1055",
        "log_types": ("linux",),
        "streams": ("siem-linux-auditd", "siem-linux-sysmon"),
    },
    {
        "technique": "T1078",
        "name": "Valid Accounts",
        "tag": "attack.t1078",
        "log_types": ("linux",),
        "streams": ("siem-linux-auditd",),
    },
    {
        "technique": "T1136",
        "name": "Create Account",
        "tag": "attack.t1136",
        "log_types": ("linux",),
        "streams": ("siem-linux-auditd", "siem-linux-sysmon"),
    },
    {
        "technique": "T1003",
        "name": "OS Credential Dumping",
        "tag": "attack.t1003",
        "log_types": ("linux",),
        "streams": ("siem-linux-auditd", "siem-linux-sysmon"),
    },
)


def credential_error(user: str, password: str, url: str) -> str | None:
    if not user or not password:
        return (
            "OPENSEARCH_USER and OPENSEARCH_PASSWORD are required. "
            "Use the read-only sigma_backtest identity "
            "(OpenBao kv/data/opensearch, field sigma_backtest_password), "
            "not kv/wazuh/indexer. Refusing to try default credentials."
        )
    if user.lower() in DENIED_USERS or password in DENIED_PASSWORDS:
        return (
            "Refusing default or break-glass OpenSearch credentials "
            "(admin, kibanaserver, and the demo passwords). "
            "Use sigma_backtest."
        )
    host = url.split("://", 1)[-1].split("/", 1)[0].lower()
    if "wazuh" in host:
        return (
            "Refusing Wazuh indexer URL %s. Detection validation queries "
            "OpenSearch Security Analytics, default %s." % (url, DEFAULT_URL)
        )
    return None


def _as_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _tags(value) -> list[str]:
    out = []
    for item in _as_list(value):
        if isinstance(item, str):
            out.append(item.strip().lower())
    return out


def _timestamp(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, (int, float)) and value > 10_000_000_000:
        # Security Analytics stores finding time as epoch milliseconds.
        seconds = value / 1000.0
        return datetime.datetime.fromtimestamp(
            seconds, datetime.timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
    return str(value)


def normalize_rule(source: dict, fallback_id: str | None = None) -> dict | None:
    if not isinstance(source, dict):
        return None
    nested = source.get("rule") if isinstance(source.get("rule"), dict) else {}
    rule_id = str(source.get("id") or nested.get("id") or fallback_id or "").strip()
    title = str(source.get("title") or nested.get("title") or rule_id or "untitled")
    tags = _tags(source.get("tags") or nested.get("tags"))
    log_type = str(
        source.get("log_type")
        or source.get("category")
        or nested.get("logsource", {}).get("product")
        or ""
    ).strip().lower()
    queries = []
    for query in _as_list(source.get("queries")):
        if isinstance(query, str) and query.strip():
            queries.append(query)
        elif isinstance(query, dict):
            text = query.get("value") or query.get("query")
            if isinstance(text, str) and text.strip():
                queries.append(text)
    if not rule_id and not tags:
        return None
    return {
        "id": rule_id or title,
        "title": title,
        "tags": tags,
        "log_type": log_type,
        "queries": queries,
    }


def rules_from_search(payload: dict) -> list[dict]:
    hits = ((payload or {}).get("hits") or {}).get("hits") or []
    rules = []
    for hit in hits:
        source = hit.get("_source") or {}
        rule = normalize_rule(source, hit.get("_id"))
        if rule:
            rules.append(rule)
    return rules


def findings_from_payload(payload: dict) -> list[dict]:
    rows = payload.get("findings")
    if rows is None:
        rows = [
            hit.get("_source") or {}
            for hit in ((payload.get("hits") or {}).get("hits") or [])
        ]
    findings = []
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        inner = row.get("finding") if isinstance(row.get("finding"), dict) else {}
        queries = row.get("queries") or inner.get("queries") or []
        timestamp = _timestamp(inner.get("timestamp") if inner else None)
        if timestamp is None:
            timestamp = _timestamp(row.get("timestamp") or row.get("@timestamp"))
        index = str(inner.get("index") or row.get("index") or row.get("_index") or "")
        if not queries:
            findings.append(
                {
                    "rule_id": str(row.get("rule_id") or row.get("id") or inner.get("id") or ""),
                    "title": str(row.get("title") or row.get("name") or ""),
                    "tags": _tags(row.get("tags")),
                    "timestamp": timestamp,
                    "index": index,
                }
            )
            continue
        for query in queries:
            if isinstance(query, str):
                continue
            if not isinstance(query, dict):
                continue
            findings.append(
                {
                    "rule_id": str(query.get("id") or ""),
                    "title": str(query.get("name") or query.get("title") or ""),
                    "tags": _tags(query.get("tags")),
                    "timestamp": timestamp,
                    "index": index,
                }
            )
    return findings


def load_sigma_dir(path: Path) -> list[dict]:
    try:
        import yaml
    except ImportError:
        sys.exit("PyYAML is required to read %s" % path)
    rules = []
    if not path.is_dir():
        return rules
    for file_path in sorted(path.rglob("*.yml")):
        try:
            document = yaml.safe_load(file_path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError):
            continue
        if not isinstance(document, dict):
            continue
        log_type = file_path.parent.name.lower()
        rule = normalize_rule(document)
        if not rule:
            continue
        # Directory name is the Security Analytics category (traefik, linux, ...).
        if log_type and log_type != "sigma":
            rule["log_type"] = log_type
        rules.append(rule)
    return rules


def merge_rules(*groups: list[dict]) -> list[dict]:
    merged: dict[str, dict] = {}
    order: list[str] = []
    for group in groups:
        for rule in group:
            key = rule["id"] or rule["title"]
            current = merged.get(key)
            if current is None:
                merged[key] = dict(rule)
                order.append(key)
                continue
            if not current["queries"] and rule["queries"]:
                current["queries"] = rule["queries"]
            if not current["tags"] and rule["tags"]:
                current["tags"] = rule["tags"]
            if not current["log_type"] and rule["log_type"]:
                current["log_type"] = rule["log_type"]
            if current["title"] in ("", "untitled") and rule["title"]:
                current["title"] = rule["title"]
    return [merged[key] for key in order]


def _index_matches(index: str, streams: tuple[str, ...]) -> bool:
    if not index:
        return True
    name = index.lstrip(".")
    return any(stream in name for stream in streams)


def _rule_matches(rule: dict, technique: dict) -> bool:
    if technique["tag"] not in rule["tags"]:
        return False
    if rule["log_type"] and rule["log_type"] not in technique["log_types"]:
        return False
    return True


def _finding_matches(finding: dict, technique: dict, rule_ids: set[str]) -> bool:
    tagged = technique["tag"] in finding["tags"]
    known_rule = finding["rule_id"] in rule_ids and finding["rule_id"] != ""
    if not tagged and not known_rule:
        return False
    return _index_matches(finding["index"], technique["streams"])


def build_report(rules: list[dict], findings: list[dict], source: str) -> dict:
    techniques = []
    for technique in TECHNIQUES:
        matched_rules = [rule for rule in rules if _rule_matches(rule, technique)]
        rule_ids = {rule["id"] for rule in matched_rules}
        matched_findings = [
            finding
            for finding in findings
            if _finding_matches(finding, technique, rule_ids)
        ]
        by_rule: dict[str, dict] = {}
        for finding in matched_findings:
            key = finding["rule_id"] or finding["title"]
            current = by_rule.get(key)
            if current is None or (finding["timestamp"] or "") > (current["timestamp"] or ""):
                by_rule[key] = finding
        rows = []
        for rule in matched_rules:
            hit = by_rule.get(rule["id"])
            rows.append(
                {
                    "id": rule["id"],
                    "title": (hit or {}).get("title") or rule["title"],
                    "status": "DETECTED" if hit else "NOT DETECTED",
                    "timestamp": (hit or {}).get("timestamp"),
                    "index": (hit or {}).get("index"),
                }
            )
        extra = [
            finding
            for key, finding in by_rule.items()
            if key not in rule_ids
        ]
        for finding in extra:
            rows.append(
                {
                    "id": finding["rule_id"],
                    "title": finding["title"] or finding["rule_id"] or technique["tag"],
                    "status": "DETECTED",
                    "timestamp": finding["timestamp"],
                    "index": finding["index"],
                }
            )
        if not matched_rules and not extra:
            status = "NO RULE"
        elif any(row["status"] == "DETECTED" for row in rows):
            status = "DETECTED"
        else:
            status = "NOT DETECTED"
        techniques.append(
            {
                "technique": technique["technique"],
                "name": technique["name"],
                "tag": technique["tag"],
                "log_types": list(technique["log_types"]),
                "streams": list(technique["streams"]),
                "status": status,
                "rules": rows,
            }
        )
    return {"source": source, "ttps": techniques}


def render_text(report: dict) -> str:
    lines = [
        "Phase 2 purple team — OpenSearch Sigma detection report",
        "source: %s" % report.get("source", "unknown"),
        "",
    ]
    for technique in report["ttps"]:
        lines.append(
            "%s %s: %s"
            % (technique["technique"], technique["name"], technique["status"])
        )
        if technique["status"] == "NO RULE":
            lines.append(
                "  no Sigma rule tagged %s for %s (%s)"
                % (
                    technique["tag"],
                    ",".join(technique["log_types"]),
                    ",".join(technique["streams"]),
                )
            )
        for rule in technique["rules"]:
            extra = ""
            if rule["status"] == "DETECTED":
                bits = []
                if rule.get("timestamp"):
                    bits.append("timestamp=%s" % rule["timestamp"])
                if rule.get("index"):
                    bits.append("index=%s" % rule["index"])
                if bits:
                    extra = " " + " ".join(bits)
            lines.append(
                "  %s %s %s%s" % (rule["id"], rule["status"], rule["title"], extra)
            )
        lines.append("")
    gaps = [item["technique"] for item in report["ttps"] if item["status"] != "DETECTED"]
    lines.append("Gaps: " + (", ".join(gaps) if gaps else "none"))
    no_rule = [item["technique"] for item in report["ttps"] if item["status"] == "NO RULE"]
    if no_rule:
        lines.append(
            "NO RULE (Sigma backlog, ESKA-1080, not Wazuh XML): " + ", ".join(no_rule)
        )
    return "\n".join(lines)


def load_fixture(path: str) -> tuple[list[dict], list[dict]]:
    with open(path, encoding="utf-8") as handle:
        payload = json.load(handle)
    if "rules" in payload or "findings" in payload:
        rules = []
        for raw in payload.get("rules") or []:
            rule = normalize_rule(raw)
            if rule:
                rules.append(rule)
        findings = []
        for raw in payload.get("findings") or []:
            findings.extend(findings_from_payload({"findings": [raw]}))
        return rules, findings
    rules = rules_from_search(payload.get("rules_search") or {})
    findings = findings_from_payload(payload.get("findings_search") or payload)
    return rules, findings


class OpenSearch:
    def __init__(self, base_url: str, user: str, password: str, cafile: str | None):
        self.base_url = base_url.rstrip("/")
        token = base64.b64encode(("%s:%s" % (user, password)).encode()).decode()
        self.auth = "Basic " + token
        self.context = ssl.create_default_context(cafile=cafile or None)

    def call(self, method: str, path: str, body: dict | None = None) -> tuple[int, dict]:
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(
            self.base_url + path,
            data=data,
            method=method,
            headers={"Authorization": self.auth, "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, context=self.context, timeout=60) as response:
                raw = response.read() or b"{}"
                return response.status, json.loads(raw.decode() or "{}")
        except urllib.error.HTTPError as exc:
            try:
                parsed = json.loads(exc.read() or b"{}")
            except json.JSONDecodeError:
                parsed = {}
            return exc.code, parsed
        except urllib.error.URLError as exc:
            sys.exit("OpenSearch unreachable: %s" % exc.reason)


def flatten_mapping(properties: dict, prefix: str = "") -> dict:
    out = {}
    for key, value in (properties or {}).items():
        name = prefix + key
        if "properties" in value:
            out.update(flatten_mapping(value["properties"], name + "."))
        else:
            out[name] = {"keyword": "keyword" in (value.get("fields") or {})}
    return out


def field_map(client: OpenSearch, streams: tuple[str, ...]) -> dict:
    status, payload = client.call("GET", "/" + ",".join(streams) + "/_mapping")
    if status != 200:
        return {}
    merged = {}
    for index in payload.values():
        merged.update(flatten_mapping((index.get("mappings") or {}).get("properties") or {}))
    return merged


def to_search_query(query: str, mapping: dict) -> str:
    """Security Analytics stores spaces as _ws_ and matches keyword text."""

    def field(match: re.Match) -> str:
        name = match.group(1)
        if mapping.get(name, {}).get("keyword"):
            return name + ".keyword:"
        return name + ":"

    rewritten = re.sub(r"(?<![\w.\\])([A-Za-z_@][\w.@-]*):", field, query)
    return rewritten.replace("_ws_", "\\ ")


def search_streams(
    client: OpenSearch, rules: list[dict], since_minutes: int
) -> list[dict]:
    findings = []
    maps: dict[tuple[str, ...], dict] = {}
    for technique in TECHNIQUES:
        streams = technique["streams"]
        if streams not in maps:
            maps[streams] = field_map(client, streams)
        mapping = maps[streams]
        for rule in rules:
            if not _rule_matches(rule, technique) or not rule["queries"]:
                continue
            for query in rule["queries"]:
                search_query = to_search_query(query, mapping)
                body = {
                    "size": 1,
                    "track_total_hits": True,
                    "sort": [{"@timestamp": "desc"}],
                    "_source": ["@timestamp"],
                    "query": {
                        "bool": {
                            "filter": [
                                {"range": {"@timestamp": {"gte": "now-%dm" % since_minutes}}},
                                {"query_string": {"query": search_query}},
                            ]
                        }
                    },
                }
                status, payload = client.call("POST", "/" + ",".join(streams) + "/_search", body)
                if status != 200:
                    print(
                        "stream query failed for %s HTTP %s" % (rule["id"], status),
                        file=sys.stderr,
                    )
                    continue
                hits = ((payload.get("hits") or {}).get("hits")) or []
                total = ((payload.get("hits") or {}).get("total") or {}).get("value", 0)
                if not total and not hits:
                    continue
                timestamp = None
                index = ",".join(streams)
                if hits:
                    timestamp = (hits[0].get("_source") or {}).get("@timestamp")
                    index = hits[0].get("_index") or index
                findings.append(
                    {
                        "rule_id": rule["id"],
                        "title": rule["title"],
                        "tags": list(rule["tags"]),
                        "timestamp": timestamp,
                        "index": index,
                    }
                )
                break
    return findings


def live_rules_and_findings(client: OpenSearch, local_rules: list[dict], since_minutes: int):
    gte_ms = int((time.time() - since_minutes * 60) * 1000)
    status, payload = client.call(
        "POST",
        "/_plugins/_security_analytics/findings/_search",
        {
            "size": 500,
            "sort": [{"timestamp": "desc"}],
            "query": {"range": {"timestamp": {"gte": gte_ms}}},
        },
    )
    rule_status, rule_payload = client.call(
        "POST",
        "/_plugins/_security_analytics/rules/_search?pre_packaged=false",
        {"size": 2000, "query": {"match_all": {}}},
    )
    deployed = rules_from_search(rule_payload) if rule_status == 200 else []
    rules = merge_rules(local_rules, deployed)
    if status == 200:
        return rules, findings_from_payload(payload), "security-analytics-findings"
    if status != 403:
        reason = (payload.get("error") or {}).get("reason") or payload
        sys.exit("findings search HTTP %s: %s" % (status, reason))
    if rule_status != 200:
        sys.exit(
            "findings API returned 403 and the rules API returned %s. "
            "sigma_backtest can search siem-* and read rules; this identity could not. "
            "Do not fall back to the Wazuh indexer." % rule_status
        )
    print(
        "findings API returned 403; scoring deployed Sigma queries against siem-* "
        "(sigma_backtest cannot read findings indices)",
        file=sys.stderr,
    )
    return rules, search_streams(client, rules, since_minutes), "siem-streams"


def default_rules_dirs() -> list[Path]:
    repo_sigma = Path(__file__).resolve().parent.parent / "sigma"
    dirs = []
    if repo_sigma.is_dir():
        dirs.append(repo_sigma)
    extra = os.environ.get("SIGMA_RULES_DIRS", "")
    for item in extra.split(":"):
        if item.strip():
            dirs.append(Path(item.strip()))
    return dirs


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--since-minutes", type=int, default=180)
    parser.add_argument("--fixture", help="JSON rules and findings. Skips the network.")
    parser.add_argument(
        "--rules-dir",
        action="append",
        default=[],
        help="Sigma directory (category subdirs). Repeatable. Defaults to ../sigma.",
    )
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument("--fail-on-gaps", action="store_true")
    args = parser.parse_args(argv)
    if args.since_minutes < 1:
        sys.exit("--since-minutes must be >= 1")

    if args.fixture:
        rules, findings = load_fixture(args.fixture)
        source = "fixture"
    else:
        url = os.environ.get("OPENSEARCH_URL", DEFAULT_URL).rstrip("/")
        user = os.environ.get("OPENSEARCH_USER", "")
        password = os.environ.get("OPENSEARCH_PASSWORD", "")
        error = credential_error(user, password, url)
        if error:
            sys.exit(error)
        directories = [Path(item) for item in args.rules_dir] or default_rules_dirs()
        local_rules: list[dict] = []
        for directory in directories:
            local_rules = merge_rules(local_rules, load_sigma_dir(directory))
        client = OpenSearch(url, user, password, os.environ.get("OPENSEARCH_CA") or None)
        rules, findings, source = live_rules_and_findings(client, local_rules, args.since_minutes)

    report = build_report(rules, findings, source)
    if args.as_json:
        print(json.dumps(report, indent=2))
    else:
        print(render_text(report))
    if args.fail_on_gaps and any(item["status"] != "DETECTED" for item in report["ttps"]):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
