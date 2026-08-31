# kspm-scanner

A lightweight **Kubernetes Security Posture Management (KSPM)** scanner. It
inspects pod/container specs — from local YAML manifests *or* a live
cluster — for common workload security misconfigurations, scores the
result, and can gate CI pipelines on what it finds.

```
$ kspm manifests examples/insecure-pod.yaml

KSPM Scanner — scanned 1 workload(s)
┏━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Severity ┃ Rule    ┃ Workload                          ┃ Container ┃ Finding                                       ┃
┡━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ CRITICAL │ KSPM001 │ Pod/legacy-app (namespace: ...)  │ app       │ Container 'app' sets privileged: true.        │
│ CRITICAL │ KSPM004 │ Pod/legacy-app (namespace: ...)  │ -         │ Pod sets hostNetwork, hostPID = true.         │
│ ...      │ ...     │ ...                               │ ...       │ ...                                            │
└──────────┴─────────┴───────────────────────────────────┴───────────┴────────────────────────────────────────────────┘
Findings — CRITICAL: 2  HIGH: 4  MEDIUM: 3  LOW: 2
Posture score: 27/100
```

## Why

Most Kubernetes security incidents don't come from a zero-day — they come
from ordinary misconfiguration: a privileged container, a pod running as
root, a `hostPath` mount, a missing resource limit. KSPM tools continuously
check workload configuration against that baseline. This project is a
small, dependency-light, hackable implementation of that idea: something
you can read end-to-end in an afternoon, run in CI, and extend.

## Features

- **Two scan sources, one rule engine.** Scan static YAML (manifests,
  Helm/kustomize render output) or a live cluster via kubeconfig — both are
  normalized into the same internal shape, so every rule runs identically
  against either.
- **11 built-in workload security rules** covering the Kubernetes Pod
  Security Standards and CIS Kubernetes Benchmark §5.2 (see table below).
- **A 0–100 posture score** per scan, weighted by finding severity.
- **Three report formats**: a colored console table, machine-readable
  JSON, and a self-contained HTML report you can archive or attach to a PR.
- **CI-friendly exit codes** via `--fail-on <SEVERITY>`.
- **Config file** (`.kspm.yaml`) for repo-wide rule/namespace exceptions.
- **Extensible by design** — adding a new rule (or a whole new category
  like RBAC or NetworkPolicy checks) is a new file with a few classes; the
  registry, CLI, and reporters need no changes. See [Architecture](#architecture).

## Install

```bash
pip install -e .
# or, without cloning:
pip install git+https://github.com/<you>/kspm-scanner.git
```

Requires Python 3.9+. Live cluster scans need read access to `pods` (the
`view` ClusterRole is sufficient).

## Usage

### Scan local manifests

```bash
kspm manifests ./k8s/                     # a directory, scanned recursively
kspm manifests ./k8s/deployment.yaml      # or a single file
```

### Scan a live cluster

```bash
kspm live                                  # all namespaces, current kube-context
kspm live --namespace payments
kspm live --context prod --exclude-namespace kube-system --exclude-namespace kube-public
```

### Report formats and CI gating

```bash
# Human-readable table (default)
kspm manifests ./k8s/

# Machine-readable JSON, written to a file
kspm manifests ./k8s/ -o json --output-file report.json

# Self-contained HTML report
kspm manifests ./k8s/ -o html --output-file report.html

# Fail the build only on CRITICAL findings; everything else is informational
kspm manifests ./k8s/ --fail-on CRITICAL

# Never fail the build (report only)
kspm manifests ./k8s/ --fail-on NONE
```

Exit code is `1` if any finding at or above `--fail-on` (default `HIGH`) is
present, `0` otherwise — drop either command into a CI job to gate merges
on workload security posture.

### Config file

Drop a `.kspm.yaml` at your repo root (see [`.kspm.yaml.example`](.kspm.yaml.example))
to set repo-wide defaults for ignored rules, excluded namespaces, and the
fail-on threshold. CLI flags always override the config file.

```yaml
ignore_rules:
  - KSPM010          # allow :latest tags in this repo
exclude_namespaces:
  - kube-system
fail_on: HIGH
```

### Docker

```bash
docker build -t kspm-scanner .
docker run --rm -v "$(pwd)":/manifests kspm-scanner manifests /manifests
docker run --rm -v ~/.kube/config:/root/.kube/config:ro kspm-scanner live
```

## Rules (v1: workload security posture)

| Rule ID | Title | Default severity | Reference |
|---|---|---|---|
| KSPM001 | Container runs in privileged mode | CRITICAL | CIS 5.2.1 |
| KSPM002 | Container may run as root | HIGH | CIS 5.2.6 |
| KSPM003 | Privilege escalation is not explicitly blocked | MEDIUM | CIS 5.2.5 |
| KSPM004 | Pod shares a host namespace (network/PID/IPC) | CRITICAL | CIS 5.2.3 / 5.2.4 |
| KSPM005 | Pod mounts a hostPath volume | HIGH | CIS 5.2.12 |
| KSPM006 | Container has no CPU/memory limits | MEDIUM | Pod Security Standards |
| KSPM007 | Root filesystem is writable | LOW | CIS 5.2.10 |
| KSPM008 | Container adds dangerous Linux capabilities | HIGH | CIS 5.2.7 / 5.2.8 / 5.2.9 |
| KSPM009 | Container binds a hostPort | MEDIUM | Pod Security Standards |
| KSPM010 | Container image uses a mutable or missing tag | LOW | Supply chain hygiene |
| KSPM011 | Service account token is auto-mounted | LOW | CIS 5.1.6 |

Every finding includes a specific remediation string; see
`kspm/rules/workload.py` for the full descriptions.

## Architecture

```
kspm/
├── models.py          # WorkloadUnit, Finding, Severity — the shared shapes
├── manifest_loader.py # static source: YAML files -> [WorkloadUnit]
├── cluster_loader.py  # live source: kubernetes client -> [WorkloadUnit]
├── rules/
│   ├── base.py         # Rule ABC + self-registering ALL_RULES list
│   └── workload.py     # the 11 rules described above
├── scanner.py         # runs rules over units, computes score/summary
├── reporters/          # console (rich), json, html
└── cli.py              # argparse entrypoint tying it all together
```

Both scan sources normalize into the same `WorkloadUnit.pod_spec` shape (a
plain dict matching the Kubernetes API's JSON schema), so rules are written
once and run identically against a YAML file or a running Pod.

**Adding a rule category** (e.g. RBAC, NetworkPolicy, admission config) is
additive: create `kspm/rules/rbac.py` with `Rule` subclasses (they
self-register via `ALL_RULES`), import that module from
`kspm/rules/__init__.py`, and optionally add a loader for the new resource
type if it isn't pod-spec-shaped. No changes needed to the CLI, scanner, or
reporters.

## Roadmap

- [ ] RBAC checks (wildcard verbs/resources, `cluster-admin` bound broadly,
      default-service-account usage)
- [ ] Network exposure checks (missing NetworkPolicies, `NodePort`/`LoadBalancer`
      services, overly broad Ingress rules)
- [ ] Secrets hygiene (secrets as env vars vs. mounted volumes, plaintext
      credentials in ConfigMaps)
- [ ] SARIF output for native GitHub code-scanning integration
- [ ] Namespace/label-based rule exceptions in `.kspm.yaml`

## Development

```bash
pip install -e ".[dev]"
pytest -q
ruff check kspm tests
```

`tests/fixtures/insecure_pod.yaml` and `tests/fixtures/hardened_deployment.yaml`
(mirrored under `examples/`) are used both as test fixtures and as a quick
way to see the scanner in action.

## License

MIT — see [LICENSE](LICENSE).
