#!/usr/bin/env python3
"""Compare installed files against lockfile expectations.

Scans the virtual environment and system directories for unexpected artifacts
that should not exist after a clean pip install. Catches backdoors, cryptominers,
cron jobs, systemd units, and rogue binaries dropped alongside legitimate packages.

Reads a pip-compile lockfile to know which packages are expected, then walks the
filesystem for anything that doesn't belong.

Usage: verify-installed-files.py <lockfile> <venv_path>
Exit code: 0 = clean, 1 = unexpected files found
"""

import json
import os
import re
import stat
import sys

SUSPICIOUS_LOCATIONS = [
    "/tmp",
    "/var/tmp",
    "/dev/shm",
    "/var/spool/cron",
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/usr/lib/systemd/system",
    "/etc/systemd/system",
]

PACKAGE_NAME_RE = re.compile(r"^([a-zA-Z0-9][a-zA-Z0-9._-]*)(?:==|\s)", re.MULTILINE)


def parse_lockfile_packages(lockfile_path: str) -> set[str]:
    with open(lockfile_path) as f:
        content = f.read()
    names = set()
    for match in PACKAGE_NAME_RE.finditer(content):
        names.add(match.group(1).lower().replace("-", "_"))
    return names


def find_unexpected_binaries(venv_path: str, expected_packages: set[str]) -> list[dict]:
    findings = []
    bin_dir = os.path.join(venv_path, "bin")
    if not os.path.isdir(bin_dir):
        return findings

    expected_bins = {
        "python", "python3", "python3.12", "pip", "pip3", "pip3.12",
        "wheel", "activate", "activate.csh", "activate.fish",
        "Activate.ps1", "gunicorn", "flask",
    }
    for name in os.listdir(bin_dir):
        path = os.path.join(bin_dir, name)
        if os.path.isfile(path) and name not in expected_bins:
            st = os.stat(path)
            if st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
                findings.append({
                    "type": "UNEXPECTED_BINARY",
                    "path": path,
                    "size": st.st_size,
                })
    return findings


def find_suspicious_system_files() -> list[dict]:
    findings = []
    for location in SUSPICIOUS_LOCATIONS:
        if not os.path.isdir(location):
            continue
        for root, dirs, files in os.walk(location):
            for name in files:
                path = os.path.join(root, name)
                try:
                    st = os.stat(path)
                except OSError:
                    continue
                if st.st_mtime > os.path.getatime(__file__) - 600:
                    findings.append({
                        "type": "SUSPICIOUS_SYSTEM_FILE",
                        "path": path,
                        "size": st.st_size,
                        "location": location,
                    })
    return findings


def find_unexpected_site_packages(venv_path: str, expected_packages: set[str]) -> list[dict]:
    findings = []
    site_packages = None
    lib_dir = os.path.join(venv_path, "lib")
    if os.path.isdir(lib_dir):
        for pydir in os.listdir(lib_dir):
            candidate = os.path.join(lib_dir, pydir, "site-packages")
            if os.path.isdir(candidate):
                site_packages = candidate
                break

    if not site_packages:
        return findings

    installed_dirs = set()
    for entry in os.listdir(site_packages):
        normalized = entry.lower().replace("-", "_").split(".")[0]
        if normalized.endswith("_info"):
            normalized = normalized.rsplit("_", 1)[0]
        installed_dirs.add(normalized)

    unexpected = installed_dirs - expected_packages - {
        "pip", "setuptools", "wheel", "pkg_resources",
        "_distutils_hack", "distutils_precedence",
        "__pycache__", "easy_install",
    }

    for pkg in unexpected:
        findings.append({
            "type": "UNEXPECTED_PACKAGE",
            "package": pkg,
            "location": site_packages,
        })

    return findings


def main() -> int:
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <lockfile> <venv_path>", file=sys.stderr)
        return 2

    lockfile_path = sys.argv[1]
    venv_path = sys.argv[2]

    expected = parse_lockfile_packages(lockfile_path)

    all_findings = []
    all_findings.extend(find_unexpected_binaries(venv_path, expected))
    all_findings.extend(find_suspicious_system_files())
    all_findings.extend(find_unexpected_site_packages(venv_path, expected))

    report = {
        "expected_packages": sorted(expected),
        "total_findings": len(all_findings),
        "findings": all_findings,
    }

    json.dump(report, sys.stdout, indent=2)
    sys.stdout.write("\n")

    return 1 if all_findings else 0


if __name__ == "__main__":
    sys.exit(main())
