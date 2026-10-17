# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The OmniSeek Authors
"""The `omniseek` command line.

    omniseek scan PATH_OR_GIT_URL [--lenses ...] [--model provider/model] [--output F] [--html F]
    omniseek verify FINDINGS --repo PATH [--ref REV] [--min-score X]
    omniseek report FINDINGS --format html|md|sarif --output F
    omniseek cloud-sync FINDINGS [--api-url URL] [--dry-run]
    omniseek rules

Exit codes: 0 success, 1 a gate failed (--fail-on, --min-score), 2 usage or input error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from ._version import __version__
from .model import LENSES, SEVERITIES, SEVERITY_RANK, FindingsError, dump_json, load_document
from .render import FORMATS, render

EXIT_OK, EXIT_GATE, EXIT_USAGE = 0, 1, 2


def _err(message: str) -> None:
    print(f"omniseek: {message}", file=sys.stderr)


def _write(path: str, content: str) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(directory):
        raise OSError(f"directory does not exist: {directory}")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)


def _severity_line(findings: list[dict]) -> str:
    counts = {s: sum(1 for f in findings if f.get("severity") == s) for s in SEVERITIES}
    return " · ".join(f"{counts[s]} {s}" for s in SEVERITIES)


def cmd_scan(args: argparse.Namespace) -> int:
    from .llm import LLMError
    from .scan import ScanError, parse_lenses, run_scan

    try:
        lenses = parse_lenses(args.lenses)
        document = run_scan(
            args.target,
            lenses=lenses,
            model=args.model,
            verify=not args.no_verify,
            keep_ungrounded=args.keep_ungrounded,
            max_context_chars=args.max_context_chars,
            timeout=args.timeout,
        )
    except (ScanError, LLMError, FileNotFoundError) as exc:
        _err(str(exc))
        return EXIT_USAGE
    written = []
    try:
        if args.output and args.output != "-":
            dump_json(document, args.output)
            written.append(args.output)
        for path, fmt in ((args.html, "html"), (args.sarif, "sarif"), (args.markdown, "md")):
            if path:
                _write(path, render(document, fmt))
                written.append(path)
    except OSError as exc:
        _err(str(exc))
        return EXIT_USAGE
    if not args.output or args.output == "-":
        sys.stdout.write(dump_json(document, None))
    findings = document["findings"]
    repo, analyzer = document["repo"], document["analyzer"]
    verification = document.get("verification") or {}
    if not args.quiet:
        mode = analyzer["mode"] + (f" with {analyzer['model']}" if analyzer.get("model") else "")
        print(
            f"OmniSeek {__version__} · scanned {repo['files_scanned']} files in {repo['name']} ({mode}; "
            f"lenses: {', '.join(analyzer['lenses'])})",
            file=sys.stderr,
        )
        grounding = f" · grounding {verification['grounding_score']:.3f}" if "grounding_score" in verification else ""
        print(f"{len(findings)} findings: {_severity_line(findings)}{grounding}", file=sys.stderr)
        llm = analyzer.get("llm")
        if llm:
            print(
                f"model: {llm['findings_proposed']} proposed, {llm['findings_rejected_malformed']} malformed, "
                f"{llm.get('dropped_ungrounded', 0)} dropped as ungrounded; {llm['files_sent']} files sent",
                file=sys.stderr,
            )
        if written:
            print("wrote " + ", ".join(written), file=sys.stderr)
    if args.fail_on:
        threshold = SEVERITY_RANK[args.fail_on]
        failing = [f for f in findings if SEVERITY_RANK[f["severity"]] <= threshold]
        if failing:
            _err(f"{len(failing)} finding(s) at or above {args.fail_on} (--fail-on)")
            return EXIT_GATE
    return EXIT_OK


def cmd_verify(args: argparse.Namespace) -> int:
    from .verify import verify_document

    try:
        document = load_document(args.findings)
    except FindingsError as exc:
        _err(str(exc))
        return EXIT_USAGE
    repo = args.repo or document.get("repo", {}).get("root") or "."
    try:
        annotated, report = verify_document(document, repo, args.ref)
    except FileNotFoundError as exc:
        _err(str(exc))
        return EXIT_USAGE
    if args.output:
        try:
            dump_json(annotated, args.output)
        except OSError as exc:
            _err(str(exc))
            return EXIT_USAGE
    if args.json:
        sys.stdout.write(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    else:
        statuses = report["citations_by_status"]
        print(
            f"OmniSeek verify · {report['findings_total']} findings, {report['citations_total']} citations "
            f"against {report['repo']} ({report['ref']})"
        )
        print(
            f"grounding_score {report['grounding_score']:.3f} · "
            + " · ".join(f"{statuses[s]} {s}" for s in statuses)
        )
        print(
            f"findings: {report['findings_grounded']} grounded · {report['findings_partially_grounded']} partially "
            f"grounded · {report['findings_ungrounded']} ungrounded"
        )
        for item in report["flagged"][:50]:
            where = ""
            if item.get("path"):
                where = f"{item['path']}:{item.get('start_line')}-{item.get('end_line')}  "
            print(f"  FLAGGED {item['status']:<16} {item['finding_id']}  {where}{item['reason']}")
        if len(report["flagged"]) > 50:
            print(f"  ... and {len(report['flagged']) - 50} more (use --json for all)")
        if not report["flagged"]:
            print("every citation checks out" if report["findings_total"] else "nothing to verify")
        if args.output:
            print(f"wrote {args.output}")
    if report["grounding_score"] < args.min_score:
        sys.stdout.flush()
        _err(f"grounding_score {report['grounding_score']:.3f} is below --min-score {args.min_score}")
        return EXIT_GATE
    return EXIT_OK


def cmd_report(args: argparse.Namespace) -> int:
    try:
        document = load_document(args.findings)
    except FindingsError as exc:
        _err(str(exc))
        return EXIT_USAGE
    if args.verify_repo:
        from .verify import verify_document

        try:
            document, _ = verify_document(document, args.verify_repo)
        except FileNotFoundError as exc:
            _err(str(exc))
            return EXIT_USAGE
    content = render(document, args.format)
    if args.output and args.output != "-":
        try:
            _write(args.output, content)
        except OSError as exc:
            _err(str(exc))
            return EXIT_USAGE
        print(f"wrote {args.output} ({args.format}, {len(document['findings'])} findings)", file=sys.stderr)
    else:
        sys.stdout.write(content)
    return EXIT_OK


def cmd_cloud_sync(args: argparse.Namespace) -> int:
    from .cloud import CloudError, build_payload, endpoint, sync

    try:
        document = load_document(args.findings)
    except FindingsError as exc:
        _err(str(exc))
        return EXIT_USAGE
    target = endpoint(args.api_url)
    if args.dry_run:
        payload = build_payload(document, include_snippets=not args.no_snippets)
        body = json.dumps(payload, indent=2, ensure_ascii=False)
        print(f"dry run: would POST {len(body.encode('utf-8')):,} bytes ({len(payload['findings'])} findings) to {target}",
              file=sys.stderr)
        sys.stdout.write(body + "\n")
        return EXIT_OK
    try:
        reply = sync(document, api_url=args.api_url, include_snippets=not args.no_snippets, timeout=args.timeout)
    except CloudError as exc:
        _err(str(exc))
        return EXIT_USAGE
    sys.stdout.write(json.dumps(reply, indent=2, ensure_ascii=False) + "\n")
    return EXIT_OK


def cmd_rules(args: argparse.Namespace) -> int:
    from .rules import RULES

    rules = [r for r in RULES.values() if not args.lens or r.lens == args.lens]
    if args.json:
        sys.stdout.write(json.dumps([r.__dict__ for r in rules], indent=2) + "\n")
        return EXIT_OK
    for rule in rules:
        print(f"{rule.id:<40} {rule.lens:<13} {rule.severity:<8} {rule.title}")
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="omniseek",
        description="Citation-grounded, multi-lens codebase intelligence. Every finding cites file:line evidence "
        "that is verified against your repository.",
    )
    parser.add_argument("--version", action="version", version=f"omniseek {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    scan = sub.add_parser("scan", help="scan a local directory or git URL")
    scan.add_argument("target", metavar="PATH_OR_REPO", help="a local directory, or an https/ssh git URL to shallow-clone")
    scan.add_argument("--lenses", default=",".join(LENSES), help=f"comma-separated subset of {','.join(LENSES)}")
    scan.add_argument("--model", help="also ask your own model: openai/<id>, anthropic/<id> or gemini/<id> "
                                      "(key from OPENAI_API_KEY, ANTHROPIC_API_KEY or GEMINI_API_KEY)")
    scan.add_argument("--output", "-o", help="write the findings JSON here (default: stdout)")
    scan.add_argument("--html", help="also write the HTML dossier here")
    scan.add_argument("--sarif", help="also write SARIF 2.1.0 here")
    scan.add_argument("--markdown", "--md", dest="markdown", help="also write Markdown here")
    scan.add_argument("--fail-on", choices=SEVERITIES, help="exit 1 if any finding is at or above this severity")
    scan.add_argument("--no-verify", action="store_true", help="skip citation verification of heuristic findings")
    scan.add_argument("--keep-ungrounded", action="store_true",
                      help="keep model findings whose citations all fail verification (dropped by default)")
    scan.add_argument("--max-context-chars", type=int, default=120_000, help="model context budget (default 120000)")
    scan.add_argument("--timeout", type=float, default=180.0, help="model request timeout in seconds")
    scan.add_argument("--quiet", "-q", action="store_true", help="no summary on stderr")
    scan.set_defaults(func=cmd_scan)

    verify = sub.add_parser("verify", help="check every citation in a findings file against a repository")
    verify.add_argument("findings", help="findings JSON (from scan, a model, or any tool using the schema)")
    verify.add_argument("--repo", help="repository directory (default: repo.root in the findings, else cwd)")
    verify.add_argument("--ref", help="verify against a git revision instead of the working tree")
    verify.add_argument("--output", "-o", help="write the findings annotated with per-citation results here")
    verify.add_argument("--min-score", type=float, default=1.0,
                        help="exit 1 when the grounding score is below this (default 1.0: every citation must verify)")
    verify.add_argument("--json", action="store_true", help="print the verification report as JSON")
    verify.set_defaults(func=cmd_verify)

    report = sub.add_parser("report", help="render findings as an HTML dossier, Markdown or SARIF")
    report.add_argument("findings")
    report.add_argument("--format", "-f", choices=FORMATS, default="html")
    report.add_argument("--output", "-o", help="output file (default: stdout)")
    report.add_argument("--verify-repo", help="verify citations against this repository first")
    report.set_defaults(func=cmd_report)

    cloud = sub.add_parser("cloud-sync", help="send findings to OmniSI Cloud (needs OMNISI_API_KEY)")
    cloud.add_argument("findings")
    cloud.add_argument("--api-url", help="API base URL (default: $OMNISI_API_URL or https://api.omnirogue.com)")
    cloud.add_argument("--no-snippets", action="store_true", help="strip quoted code and excerpts before sending")
    cloud.add_argument("--dry-run", action="store_true", help="print the payload instead of sending it")
    cloud.add_argument("--timeout", type=float, default=60.0)
    cloud.set_defaults(func=cmd_cloud_sync)

    rules = sub.add_parser("rules", help="list the built-in heuristic rules")
    rules.add_argument("--lens", choices=LENSES)
    rules.add_argument("--json", action="store_true")
    rules.set_defaults(func=cmd_rules)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130
    except BrokenPipeError:
        return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
