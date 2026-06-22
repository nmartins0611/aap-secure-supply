# Trusted Build Pipeline for Ansible Automation Platform

A seven-step application-level supply chain security pipeline that goes beyond scanning and signing. AAP controls the build environment itself -- locking dependencies, isolating the network, monitoring install behavior, verifying what got installed, and enforcing policy at deployment.

## What This Does

```
DEVELOPER COMMITS CODE
  │
  ├─ Step 1: Validate lockfile (hashes + approved allowlist)
  │
  ├─ Step 2: Private mirror intake (scan + approve new packages) ← EDA triggered
  │
  ├─ Step 3: Block network during build (nftables isolation)
  │     │
  │     ├─ Step 4: Monitor install behavior (disposable container + auditd)
  │     │
  │     └─ Step 5: Verify installed files (compare disk to lockfile)
  │
  ├─ Step 6: Build, scan, sign image (SBOM + cosign + SLSA provenance)
  │
  └─ Step 7: Admission control at deployment (signature + SBOM + CVE gate)
```

Steps 3 and 4 are what no other tool does. IBM Concert, Snyk, JFrog -- they detect and report. This pipeline controls the infrastructure the build runs on and monitors what packages actually do when they install.

## Quick Start

### 1. Build the Custom Execution Environment

```bash
cd execution-environment/
ansible-builder build \
  --tag trusted-pipeline-ee:latest \
  --container-runtime podman
podman push trusted-pipeline-ee:latest quay.io/aap-supply-chain/trusted-pipeline-ee:latest
```

### 2. Prepare the Execution Node

```bash
# On the RHEL 9 execution node
sudo systemctl enable --now podman.socket
sudo mkdir -p /opt/trusted-pipeline/reports
sudo chown ansible:ansible /opt/trusted-pipeline
sudo mkdir -p /etc/nftables
```

### 3. Configure AAP

#### AAP Project

| Field | Value |
|-------|-------|
| Name | `Trusted Build Pipeline` |
| SCM Type | Git |
| SCM URL | URL of this repository |
| Update Revision on Launch | Enabled |

#### Instance Group

Add these container options to the instance group used by your execution node:

```
DEFAULT_CONTAINER_OPTIONS:
  - "--volume=/run/podman/podman.sock:/run/podman/podman.sock:ro"
  - "--volume=/opt/trusted-pipeline:/opt/trusted-pipeline:rw"
```

#### Credentials

| Credential | Type | Purpose |
|---|---|---|
| `registry.redhat.io` pull secret | Container Registry | Pull UBI base images |
| Quay.io push credential | Container Registry | Push built/signed images |
| Internal PyPI mirror | Custom | Mirror intake uploads (Step 2) |
| Slack webhook | Custom | Pipeline failure notifications |
| Splunk HEC token | Custom | Audit logging (optional) |
| SCM credential | Source Control | Clone this repository |

**Custom Credential Type for Slack:**

Input:
```yaml
fields:
  - id: slack_webhook_url
    type: string
    label: Slack Webhook URL
    secret: true
required:
  - slack_webhook_url
```

Injector:
```yaml
extra_vars:
  slack_webhook_url: "{{ slack_webhook_url }}"
```

#### Job Templates

| Job Template | Playbook | EE | Notes |
|---|---|---|---|
| `Step 1 - Validate Lockfile` | `playbooks/01-validate-lockfile.yml` | `trusted-pipeline-ee` | |
| `Step 2 - Mirror Intake` | `playbooks/02-mirror-intake.yml` | `trusted-pipeline-ee` | Needs `mirror_package_name` + `mirror_package_version` extra vars |
| `Step 3a - Apply Network Isolation` | `playbooks/03-apply-network-isolation.yml` | `trusted-pipeline-ee` | Needs privilege escalation |
| `Step 3b - Revert Network Isolation` | `playbooks/03-revert-network-isolation.yml` | `trusted-pipeline-ee` | Needs privilege escalation |
| `Step 4 - Behavioral Monitor` | `playbooks/04-behavioral-monitor.yml` | `trusted-pipeline-ee` | |
| `Step 5 - Post-Install Verify` | `playbooks/05-post-install-verify.yml` | `trusted-pipeline-ee` | |
| `Step 6 - Golden Image Build` | `playbooks/06-golden-image-build.yml` | `trusted-pipeline-ee` | Needs Quay.io + Sigstore creds |
| `Step 7 - Admission Control` | `playbooks/07-admission-control.yml` | `trusted-pipeline-ee` | Runs against deploy_targets |
| `Failure Report` | `playbooks/helpers/failure-report.yml` | Default EE | Needs Slack + Splunk creds |

#### Workflow Template

Create a workflow template called `Trusted Build Pipeline` with this layout:

```
[Step 1: Validate Lockfile]
    │ success
    ▼
[Step 3a: Apply Network Isolation]
    │ success
    ▼
[Step 4: Behavioral Monitor]
    │ success
    ▼
[Step 5: Post-Install Verify]
    │ success
    ▼
[Step 3b: Revert Network Isolation]
    │ success
    ▼
[Step 6: Golden Image Build]
    │
    ├─ failure at any step ──► [Failure Report] + [Step 3b: Revert Isolation]
    │
    ▼ success
Pipeline complete
```

Enable **Artifact passing** so `set_stats` data flows between jobs (enabled by default).

#### EDA Rulebook Activations

| Activation | Rulebook | Trigger |
|---|---|---|
| `PyPI Package Monitor` | `rulebooks/upstream-package-monitor.yml` | Polls PyPI RSS every 5 min |
| `RHSA Advisory Trigger` | `rulebooks/advisory-rebuild-trigger.yml` | Webhook on port 5000 |

### 4. Configure Policies

Edit these files before your first run:

- `policies/approved-packages.yml` -- Add your approved Python packages
- `policies/network-allowlist.yml` -- Set your internal mirror and registry IPs
- `policies/admission/image-admission.rego` -- Set your approved registries and golden base repos
- `group_vars/all.yml` -- Set your registry URL, mirror URL, and notification endpoints

### 5. Run the Pipeline

**Option A -- Full workflow via AAP:**

Launch the `Trusted Build Pipeline` workflow template from the AAP Controller UI.

**Option B -- Single playbook locally (for testing):**

```bash
ansible-playbook playbooks/trusted-build-pipeline.yml
```

**Option C -- Individual steps:**

```bash
# Test lockfile validation with the typosquatting scenario
ansible-playbook playbooks/01-validate-lockfile.yml \
  -e lockfile_path_override=sample-app/scenarios/typosquat/requirements.lock
```

## Demo Scenarios

The `sample-app/scenarios/` directory contains four lockfiles for demonstrating each failure mode:

| Scenario | Lockfile | Expected Result |
|---|---|---|
| `clean/` | All approved, all hashed | PASS all steps |
| `typosquat/` | Contains `reqeusts` | FAIL Step 1 -- blocked package |
| `unapproved/` | Contains `colorama` (not on allowlist) | FAIL Step 1 -- unapproved dependency |
| `malicious-postinstall/` | Contains package that reads /etc/shadow and phones home | FAIL Step 4 -- behavioral violations |

See [DEMO.md](DEMO.md) for the full walkthrough with talking points.

## Project Structure

```
aap-full-trusted-pipeline/
├── README.md                              # This file
├── BOM.md                                 # Bill of materials (full deployment requirements)
├── DEMO.md                                # Demo walkthrough with talking points
├── CLAUDE.md                              # Project context for AI-assisted development
├── execution-environment/
│   └── execution-environment.yml          # Custom EE definition
├── playbooks/
│   ├── trusted-build-pipeline.yml         # Master orchestrator (Steps 1-6)
│   ├── 01-validate-lockfile.yml           # Step 1
│   ├── 02-mirror-intake.yml              # Step 2
│   ├── 03-apply-network-isolation.yml    # Step 3a
│   ├── 03-revert-network-isolation.yml   # Step 3b
│   ├── 04-behavioral-monitor.yml          # Step 4
│   ├── 05-post-install-verify.yml         # Step 5
│   ├── 06-golden-image-build.yml          # Step 6
│   ├── 07-admission-control.yml           # Step 7
│   └── helpers/failure-report.yml         # Failure notifications
├── roles/
│   ├── lockfile_validator/                # Step 1
│   ├── mirror_gatekeeper/                 # Step 2
│   ├── build_network_isolation/           # Step 3
│   ├── install_monitor/                   # Step 4
│   ├── post_install_verifier/             # Step 5
│   └── admission_enforcer/               # Step 7
├── policies/
│   ├── approved-packages.yml              # Package allowlist
│   ├── network-allowlist.yml              # Build firewall allowlist
│   └── admission/image-admission.rego    # OPA admission policy
├── rulebooks/
│   ├── upstream-package-monitor.yml       # EDA: PyPI watcher
│   └── advisory-rebuild-trigger.yml       # EDA: RHSA webhook
├── sample-app/                            # Demo application + attack scenarios
├── group_vars/all.yml                     # Configuration variables
├── inventory/hosts.yml                    # Host inventory
└── collections/requirements.yml           # Ansible collection dependencies
```

## Related Work

- [golden-image-pipeline](../golden-image-pipeline/) -- Trusted Golden Image Pipeline (Step 6 in detail)
- [image-control](../image-control/) -- Image Admission Control (Step 7 in detail)
