"""This module contains the functions to handle dependency vulnerability scan operations."""

import json
import tempfile
from pathlib import Path
from mega_snake.util.util import run_operation

ISSUE_SEARCH_TAG: str = "[dependency-scan]"


def export_requirements() -> str:
    """
    Exports the project's locked dependencies from `uv.lock` into a pip-audit-compatible requirements file.

    Returns:
        str: Path to the generated requirements file.
    """
    requirements_path: str = str(Path(tempfile.gettempdir()) / "mega_snake_dependency_scan_requirements.txt")
    cwd: str = f"uv export --no-hashes --format requirements-txt -o {requirements_path}"
    run_operation(cwd, "Exporting locked dependencies with uv")
    return requirements_path


def run_pip_audit(requirements_path: str) -> str:
    """
    Runs `pip-audit` against the given requirements file and returns its JSON report.

    Args:
        requirements_path: str

    Returns:
        str: Raw JSON output produced by pip-audit. pip-audit exits with a non-zero status when
            vulnerabilities are found, so failures are not treated as errors here.
    """
    cwd: str = f"pip-audit -r {requirements_path} --format json --progress-spinner off"
    return run_operation(cwd, "Auditing dependencies with pip-audit", check=False).stdout.strip()


def get_existing_issue_titles() -> set[str]:
    """
    Retrieves the titles of existing open and closed GitHub issues previously filed by the dependency scanner,
    used to avoid creating duplicate issues for findings that were already reported.

    Returns:
        set[str]: Titles of existing dependency-scan issues.
    """
    cwd: str = f'gh issue list --state all --search "{ISSUE_SEARCH_TAG} in:title" --limit 200 --json title'
    result: str = run_operation(cwd, "Listing existing dependency-scan issues").stdout.strip()
    if not result:
        return set()
    issues: list[dict] = json.loads(result)
    return {issue["title"] for issue in issues}


def create_issue(title: str, body: str) -> None:
    """
    Creates a new GitHub issue for a dependency vulnerability finding.

    Args:
        title: str
        body: str

    Returns:
        None
    """
    body_path: str = str(Path(tempfile.gettempdir()) / "mega_snake_dependency_scan_issue_body.md")
    Path(body_path).write_text(body, encoding="utf-8")
    cwd: str = f'gh issue create --title "{title}" --body-file {body_path}'
    run_operation(cwd, f"Creating issue for {title}")
