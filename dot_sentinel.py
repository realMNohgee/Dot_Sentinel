#!/usr/bin/env python3
"""Dot_Sentinel — .env security scanner. Detect secrets, missing vars, weak values. Zero deps.

Domains: DevSecOps | CI/CD pipelines | compliance audit | secrets management
"""
from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any


# ── Pattern library ────────────────────────────────────────────────────────
SECRET_PATTERNS: dict[str, str] = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])",
    "Stripe Live Secret": r"sk_live_[0-9a-zA-Z]{24,}",
    "Stripe Live Publishable": r"pk_live_[0-9a-zA-Z]{24,}",
    "Stripe Test Secret": r"sk_test_[0-9a-zA-Z]{24,}",
    "Stripe Test Publishable": r"pk_test_[0-9a-zA-Z]{24,}",
    "GitHub Token (classic)": r"ghp_[0-9a-zA-Z]{36}",
    "GitHub Token (fine-grained)": r"github_pat_[0-9a-zA-Z_]{22,}",
    "GitHub App Installation": r"ghs_[0-9a-zA-Z]{36,}",
    "GitHub Refresh Token": r"ghr_[0-9a-zA-Z]{36,}",
    "Private Key": r"-----BEGIN\s.*PRIVATE KEY-----",
    "JWT Token": r"eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]+",
    "Slack Webhook": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
    "Slack Bot Token": r"xox[baprs]-[0-9]+-[0-9]+-[a-zA-Z0-9]+",
    "Telegram Bot Token": r"\b[0-9]+:[a-zA-Z0-9_-]{35}\b",
    "DB URL with Password": r"(?:mysql|postgres|postgresql|mongodb|redis|sqlite)://[^:]+:[^@]+@",
    "Generic API Key (heur.)": r"(?:api[_-]?key|apikey|secret|token|password|passwd)\s*[:=]\s*\S{8,}",
}


def _shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string in bits per character."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


ENTROPY_THRESHOLD = 4.5


# ── Format helper ──────────────────────────────────────────────────────────
def _output(data: Any, fmt: str) -> int:
    if fmt == "json":
        print(json.dumps(data, indent=2))
    else:
        _print_text(data)
    return 0


def _print_text(data: Any, indent: int = 0) -> None:
    prefix = "  " * indent
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                _print_text(item, indent + 1)
                print()
            else:
                print(f"{prefix}• {item}")
    elif isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, list):
                print(f"{prefix}{key}:")
                for item in value:
                    if isinstance(item, dict):
                        _print_text(item, indent + 1)
                        print()
                    else:
                        print(f"{prefix}  • {item}")
            elif isinstance(value, dict):
                print(f"{prefix}{key}:")
                _print_text(value, indent + 1)
            else:
                print(f"{prefix}{key}: {value}")
    else:
        print(f"{prefix}{data}")


# ── .env parsing ───────────────────────────────────────────────────────────
def _parse_env(path: str | Path) -> dict[str, str]:
    """Parse a .env file, returning {KEY: value}."""
    result: dict[str, str] = {}
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if "=" in stripped:
                key, _, value = stripped.partition("=")
                result[key.strip()] = value.strip()
    return result


# ── scan ───────────────────────────────────────────────────────────────────
def _cmd_scan(args: argparse.Namespace) -> int:
    path = Path(args.path)
    if not path.is_file():
        print(f"Error: {args.path} is not a file", file=sys.stderr)
        return 1

    # Load custom patterns
    patterns: dict[str, str] = dict(SECRET_PATTERNS)
    if args.patterns:
        try:
            with open(args.patterns, "r", encoding="utf-8") as pf:
                for line in pf:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if ":" in line:
                        name, _, regex = line.partition(":")
                        patterns[name.strip()] = regex.strip()
        except OSError as e:
            print(f"Error reading patterns file: {e}", file=sys.stderr)
            return 1

    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    findings: list[dict[str, Any]] = []
    seen_spans: set[tuple[int, int]] = set()

    for name, pattern in patterns.items():
        try:
            compiled = re.compile(pattern)
        except re.error as e:
            print(f"Warning: invalid pattern '{name}': {e}", file=sys.stderr)
            continue
        for m in compiled.finditer(content):
            span = (m.start(), m.end())
            if span in seen_spans:
                continue
            seen_spans.add(span)
            start_line = content[: m.start()].count("\n") + 1
            findings.append({
                "type": name,
                "value": m.group(),
                "line": start_line,
            })

    # High-entropy detection
    if args.high_entropy:
        # Find long-enough strings (potential secrets embedded in config)
        for m in re.finditer(r"[A-Za-z0-9+/=_-]{20,}", content):
            span = (m.start(), m.end())
            if span in seen_spans:
                continue
            candidate = m.group()
            entropy = _shannon_entropy(candidate)
            if entropy > ENTROPY_THRESHOLD:
                seen_spans.add(span)
                start_line = content[: m.start()].count("\n") + 1
                findings.append({
                    "type": f"high-entropy string (entropy={entropy:.2f})",
                    "value": candidate,
                    "line": start_line,
                })

    result: dict[str, Any] = {
        "file": str(path),
        "findings_count": len(findings),
        "findings": findings,
    }
    return _output(result, args.format)


# ── compare ────────────────────────────────────────────────────────────────
def _cmd_compare(args: argparse.Namespace) -> int:
    env1_path = Path(args.env1)
    env2_path = Path(args.env2)
    for p, name in [(env1_path, "env1"), (env2_path, "env2")]:
        if not p.is_file():
            print(f"Error: {name} ({p}) is not a file", file=sys.stderr)
            return 1

    env1 = _parse_env(env1_path)
    env2 = _parse_env(env2_path)

    keys1 = set(env1.keys())
    keys2 = set(env2.keys())

    added = sorted(keys2 - keys1)
    removed = sorted(keys1 - keys2)
    common = keys1 & keys2
    changed = sorted(k for k in common if env1[k] != env2[k])

    result = {
        "file1": str(env1_path),
        "file2": str(env2_path),
        "added_keys": added,
        "removed_keys": removed,
        "changed_keys": changed,
    }
    return _output(result, args.format)


# ── template ───────────────────────────────────────────────────────────────
def _cmd_template(args: argparse.Namespace) -> int:
    path = Path(args.sample)
    if not path.is_file():
        print(f"Error: {args.sample} is not a file", file=sys.stderr)
        return 1

    env = _parse_env(path)
    lines: list[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if not stripped:
                lines.append("")
            elif stripped.startswith("#"):
                lines.append(line.rstrip("\n"))
            elif "=" in stripped:
                key = stripped.partition("=")[0].strip()
                lines.append(f"{key}=")
            else:
                lines.append(line.rstrip("\n"))

    result = {
        "source": str(path),
        "keys": sorted(env.keys()),
        "template": "\n".join(lines),
    }
    return _output(result, args.format)


# ── audit ──────────────────────────────────────────────────────────────────
def _cmd_audit(args: argparse.Namespace) -> int:
    root = Path(args.directory)
    if not root.is_dir():
        print(f"Error: {args.directory} is not a directory", file=sys.stderr)
        return 1

    results: list[dict[str, Any]] = []
    # Find .env* files
    env_files = sorted(root.rglob(".env*"))
    # Also find *.env files
    env_files += sorted(root.rglob("*.env"))
    # Deduplicate
    seen: set[str] = set()
    unique_files: list[Path] = []
    for f in env_files:
        if f.name.startswith(".") or f.name.endswith(".env"):
            if str(f) not in seen:
                seen.add(str(f))
                unique_files.append(f)

    for env_file in unique_files:
        rel = str(env_file.relative_to(root))
        try:
            env = _parse_env(env_file)
        except Exception:
            continue

        # Check for secrets using built-in patterns
        with open(env_file, "r", encoding="utf-8") as f:
            content = f.read()
        secrets_found: list[dict[str, Any]] = []
        for name, pattern in SECRET_PATTERNS.items():
            try:
                compiled = re.compile(pattern)
            except re.error:
                continue
            for m in compiled.finditer(content):
                start_line = content[: m.start()].count("\n") + 1
                secrets_found.append({
                    "type": name,
                    "value": m.group(),
                    "line": start_line,
                })

        # Check .gitignore coverage
        gitignore_path = root / ".gitignore"
        gitignored = False
        if gitignore_path.is_file():
            with open(gitignore_path, "r", encoding="utf-8") as gf:
                gitignore_lines = gf.read().splitlines()
            for giline in gitignore_lines:
                giline = giline.strip()
                if not giline or giline.startswith("#"):
                    continue
                # Simple pattern matching
                pattern_str = giline.lstrip("/")
                basename = rel.replace("\\", "/").split("/")[-1]
                if pattern_str == rel or (
                    pattern_str.endswith("*") and rel.startswith(pattern_str.rstrip("*"))
                ) or (
                    "*" in pattern_str and re.match(
                        pattern_str.replace(".", r"\.").replace("*", ".*"), rel
                    )
                ) or (
                    "/" not in pattern_str and pattern_str == basename
                ):
                    gitignored = True
                    break

        results.append({
            "file": rel,
            "keys_count": len(env),
            "has_secrets": len(secrets_found) > 0,
            "secrets": secrets_found,
            "gitignored": gitignored,
        })

    summary = {
        "directory": str(root),
        "files_scanned": len(results),
        "files_with_secrets": sum(1 for r in results if r["has_secrets"]),
        "files_not_gitignored": sum(1 for r in results if not r["gitignored"]),
        "files": results,
    }
    return _output(summary, args.format)


# ── mask ───────────────────────────────────────────────────────────────────
def _cmd_mask(args: argparse.Namespace) -> int:
    path = Path(args.file)
    if not path.is_file():
        print(f"Error: {args.file} is not a file", file=sys.stderr)
        return 1

    lines: list[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if not stripped:
                lines.append("")
            elif stripped.startswith("#"):
                lines.append(line.rstrip("\n"))
            elif "=" in stripped:
                key, sep, value = stripped.partition("=")
                lines.append(f"{key}{sep}***")
            else:
                lines.append(line.rstrip("\n"))

    output = "\n".join(lines)
    if args.format == "json":
        print(json.dumps({"file": str(path), "masked": output}, indent=2))
    else:
        print(output)
    return 0


# ── CLI builder ────────────────────────────────────────────────────────────
def _add_format(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--format", choices=["text", "json"], default="text",
        help="Output format (default: text)"
    )


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description=".env security scanner — detect secrets, missing vars, weak values.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Zero dependencies. Pure Python stdlib.\n🧰 https://hermtica.com/marketplace",
    )
    sub = p.add_subparsers(dest="command")

    # scan
    p_scan = sub.add_parser("scan", help="Scan a .env file for secrets")
    p_scan.add_argument("path", help="Path to .env file")
    p_scan.add_argument("--high-entropy", action="store_true", help="Flag high-entropy strings (>4.5 bits/char)")
    p_scan.add_argument("--patterns", metavar="FILE", help="Custom patterns file (one per line: name:regex)")
    _add_format(p_scan)

    # compare
    p_comp = sub.add_parser("compare", help="Compare two .env files")
    p_comp.add_argument("env1", help="First .env file")
    p_comp.add_argument("env2", help="Second .env file")
    _add_format(p_comp)

    # template
    p_tmpl = sub.add_parser("template", help="Extract keys and output a template with empty values")
    p_tmpl.add_argument("sample", help="Sample .env file")
    _add_format(p_tmpl)

    # audit
    p_audit = sub.add_parser("audit", help="Recursively audit .env* files in directory")
    p_audit.add_argument("directory", help="Root directory to scan")
    _add_format(p_audit)

    # mask
    p_mask = sub.add_parser("mask", help="Print .env with values replaced by ***")
    p_mask.add_argument("file", help="Path to .env file")
    _add_format(p_mask)

    args = p.parse_args(argv)

    if args.command == "scan":
        return _cmd_scan(args)
    elif args.command == "compare":
        return _cmd_compare(args)
    elif args.command == "template":
        return _cmd_template(args)
    elif args.command == "audit":
        return _cmd_audit(args)
    elif args.command == "mask":
        return _cmd_mask(args)
    else:
        p.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
