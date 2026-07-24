#!/usr/bin/env python3
"""
Audits project dependencies for known vulnerabilities and files GitHub issues for new findings.
"""

import click
import mega_snake.light_weight.dependency_scan_handler as handler
from mega_snake.light_weight.vulnerability import Vulnerability, parse_pip_audit_output
from mega_snake.util.formatting import ws_info, ws_success, ws_warning


@click.command(
    name="scan-dependencies",
    short_help="Audits project dependencies for known vulnerabilities and files GitHub issues for new findings.",
    help="""Audits the project's locked dependencies (uv.lock) with pip-audit against the OSV advisory
    database, then files a GitHub issue for each vulnerability that has not already been reported.""",
    epilog="""
    usage: mgsnake scan-dependencies [--dry-run]\n
    Options:\n
        --dry-run: Print findings without creating GitHub issues.
    """,
)
@click.option("--dry-run", is_flag=True, help="Print findings without creating GitHub issues.")
def scan_dependencies(dry_run: bool) -> None:
    """
    Audits project dependencies for known vulnerabilities and files GitHub issues for new findings.

    Args:
        dry_run: bool

    Returns:
        None
    """
    requirements_path: str = handler.export_requirements()
    raw_output: str = handler.run_pip_audit(requirements_path)
    vulnerabilities: list[Vulnerability] = parse_pip_audit_output(raw_output)

    if not vulnerabilities:
        ws_success("No known vulnerabilities found in the project's dependencies.")
        return

    ws_warning(f"Found {len(vulnerabilities)} vulnerability finding(s).")

    if dry_run:
        for vulnerability in vulnerabilities:
            ws_info(vulnerability.issue_title)
        return

    existing_titles: set[str] = handler.get_existing_issue_titles()
    created_count: int = 0
    for vulnerability in vulnerabilities:
        if vulnerability.issue_title in existing_titles:
            ws_info(f"Skipping already reported finding: {vulnerability.issue_title}")
            continue
        handler.create_issue(vulnerability.issue_title, vulnerability.issue_body())
        created_count += 1

    ws_success(f"Created {created_count} new issue(s) for dependency vulnerabilities.")
