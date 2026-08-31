from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console

from kspm import __version__
from kspm.config import KspmConfig, find_default_config, load_config
from kspm.models import Severity
from kspm.reporters import render_console, render_html, render_json
from kspm.scanner import run_rules

_SEVERITY_CHOICES = [s.value for s in Severity] + ["NONE"]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kspm",
        description="KSPM Scanner — Kubernetes Security Posture Management "
        "scanner for workload misconfigurations.",
    )
    parser.add_argument("--version", action="version", version=f"kspm-scanner {__version__}")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "-o", "--output", choices=["console", "json", "html"], default="console",
        help="Report format (default: console).",
    )
    common.add_argument(
        "--output-file", type=Path, default=None,
        help="Write the report to this file instead of stdout "
        "(required/implied for html; optional for json).",
    )
    common.add_argument(
        "--fail-on", choices=_SEVERITY_CHOICES, default=None,
        help="Exit non-zero if any finding at or above this severity is "
        "present. Use NONE to always exit 0. Overrides .kspm.yaml.",
    )
    common.add_argument(
        "--ignore-rule", action="append", default=[], metavar="RULE_ID",
        help="Rule ID to skip (repeatable). Merged with .kspm.yaml.",
    )
    common.add_argument(
        "--config", type=Path, default=None,
        help="Path to a .kspm.yaml config file (default: ./.kspm.yaml if present).",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    manifests_parser = subparsers.add_parser(
        "manifests", parents=[common],
        help="Scan local YAML manifests (files or a directory tree).",
    )
    manifests_parser.add_argument(
        "path", type=Path, help="File or directory containing Kubernetes YAML manifests.",
    )

    live_parser = subparsers.add_parser(
        "live", parents=[common],
        help="Scan Pods in a live cluster via kubeconfig / in-cluster credentials.",
    )
    live_parser.add_argument("--namespace", default=None, help="Limit the scan to one namespace.")
    live_parser.add_argument("--context", default=None, help="kubeconfig context to use.")
    live_parser.add_argument(
        "--exclude-namespace", action="append", default=[], metavar="NAMESPACE",
        help="Namespace to skip (repeatable). Merged with .kspm.yaml.",
    )

    return parser


def _resolve_config(args: argparse.Namespace) -> KspmConfig:
    config_path = args.config or find_default_config(Path.cwd())
    config = load_config(config_path)
    config.ignore_rules = sorted(set(config.ignore_rules) | set(args.ignore_rule))
    if args.fail_on:
        config.fail_on = args.fail_on
    return config


def _load_units(args: argparse.Namespace, config: KspmConfig):
    if args.command == "manifests":
        from kspm.manifest_loader import load_workloads_from_path

        if not args.path.exists():
            print(f"error: path not found: {args.path}", file=sys.stderr)
            sys.exit(2)
        return load_workloads_from_path(args.path)

    if args.command == "live":
        from kspm.cluster_loader import ClusterConnectionError, load_workloads_from_cluster

        exclude = tuple(sorted(set(config.exclude_namespaces) | set(args.exclude_namespace)))
        try:
            return load_workloads_from_cluster(
                namespace=args.namespace, context=args.context, exclude_namespaces=exclude,
            )
        except ClusterConnectionError as exc:
            print(f"error: {exc}", file=sys.stderr)
            sys.exit(2)

    raise AssertionError(f"unknown command: {args.command}")  # pragma: no cover


def _emit_report(findings, scanned_count: int, args: argparse.Namespace) -> None:
    if args.output == "console":
        render_console(findings, scanned_count, console=Console())
        return

    text = render_json(findings, scanned_count) if args.output == "json" else render_html(
        findings, scanned_count
    )

    if args.output_file:
        args.output_file.write_text(text, encoding="utf-8")
        print(f"Report written to {args.output_file}")
    else:
        print(text)


def _exit_code(findings, fail_on: str) -> int:
    if fail_on == "NONE":
        return 0
    threshold = Severity(fail_on)
    if any(f.severity.rank <= threshold.rank for f in findings):
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    config = _resolve_config(args)

    units = _load_units(args, config)
    findings = run_rules(units, ignored_rule_ids=config.ignore_rules)
    _emit_report(findings, scanned_count=len(units), args=args)

    return _exit_code(findings, config.fail_on)


if __name__ == "__main__":
    sys.exit(main())
