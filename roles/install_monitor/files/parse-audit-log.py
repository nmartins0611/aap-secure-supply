#!/usr/bin/env python3
"""Parse auditd log from a monitored pip install and flag violations.

Reads the audit log from stdin or a file argument, classifies events by key,
and outputs a JSON report of violations. Exit code 0 = clean, 1 = violations found.

Violation categories:
  SECRET_READ      - attempted read of credential files (/etc/shadow, SSH keys, etc.)
  UNEXPECTED_WRITE - write outside the virtual environment or pip cache
  ROGUE_EXEC       - execution of a binary from /tmp, /var/tmp, or /dev/shm
  NETWORK_EXFIL    - outbound network connection (connect syscall)
"""

import json
import re
import sys
from typing import TextIO

VIOLATION_KEYS = {
    "secret_read": "SECRET_READ",
    "unexpected_write": "UNEXPECTED_WRITE",
    "rogue_exec": "ROGUE_EXEC",
    "network_connect": "NETWORK_EXFIL",
    "dns_lookup": "NETWORK_EXFIL",
}

TIMESTAMP_RE = re.compile(r"msg=audit\((\d+\.\d+):\d+\)")
KEY_RE = re.compile(r'key="([^"]+)"')
EXE_RE = re.compile(r'exe="([^"]+)"')
NAME_RE = re.compile(r'name="([^"]+)"')
COMM_RE = re.compile(r'comm="([^"]+)"')


def parse_event(line: str) -> dict | None:
    key_match = KEY_RE.search(line)
    if not key_match:
        return None

    key = key_match.group(1)
    if key not in VIOLATION_KEYS:
        return None

    timestamp = ""
    ts_match = TIMESTAMP_RE.search(line)
    if ts_match:
        timestamp = ts_match.group(1)

    exe = ""
    exe_match = EXE_RE.search(line)
    if exe_match:
        exe = exe_match.group(1)

    name = ""
    name_match = NAME_RE.search(line)
    if name_match:
        name = name_match.group(1)

    comm = ""
    comm_match = COMM_RE.search(line)
    if comm_match:
        comm = comm_match.group(1)

    return {
        "category": VIOLATION_KEYS[key],
        "audit_key": key,
        "timestamp": timestamp,
        "executable": exe,
        "target": name,
        "command": comm,
        "raw": line.strip(),
    }


def parse_audit_log(stream: TextIO) -> list[dict]:
    violations = []
    for line in stream:
        event = parse_event(line)
        if event is not None:
            violations.append(event)
    return violations


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] != "-":
        with open(sys.argv[1], "r") as f:
            violations = parse_audit_log(f)
    else:
        violations = parse_audit_log(sys.stdin)

    report = {
        "total_violations": len(violations),
        "categories": {},
        "violations": violations,
    }

    for v in violations:
        cat = v["category"]
        report["categories"][cat] = report["categories"].get(cat, 0) + 1

    json.dump(report, sys.stdout, indent=2)
    sys.stdout.write("\n")

    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())
