"""Tests for dependency_scan.py"""

from unittest.mock import patch, MagicMock
from mega_snake.light_weight.dependency_scan import scan_dependencies
from mega_snake.light_weight.vulnerability import Vulnerability


def _vuln(vuln_id: str) -> Vulnerability:
    """Build a minimal Vulnerability for tests."""
    return Vulnerability(
        package="requests",
        installed_version="2.25.0",
        vuln_id=vuln_id,
        fix_versions=["2.31.0"],
        aliases=[],
        description="desc",
        severity="HIGH",
    )


def test_scan_dependencies_no_findings() -> None:
    """No vulnerabilities found should report success and never touch issues."""
    with patch(
        "mega_snake.light_weight.dependency_scan.handler.export_requirements", return_value="/tmp/req.txt"
    ), patch("mega_snake.light_weight.dependency_scan.handler.run_pip_audit", return_value="{}"), patch(
        "mega_snake.light_weight.dependency_scan.handler.get_existing_issue_titles"
    ) as get_titles, patch(
        "mega_snake.light_weight.dependency_scan.handler.create_issue"
    ) as create_issue, patch(
        "mega_snake.light_weight.dependency_scan.ws_success"
    ) as ws_success:
        scan_dependencies.callback(False)
        ws_success.assert_called_once()
        get_titles.assert_not_called()
        create_issue.assert_not_called()


def test_scan_dependencies_dry_run_prints_findings_without_creating_issues() -> None:
    """Dry-run mode should print findings and never create issues."""
    vulnerabilities = [_vuln("PYSEC-1"), _vuln("PYSEC-2")]
    with patch(
        "mega_snake.light_weight.dependency_scan.handler.export_requirements", return_value="/tmp/req.txt"
    ), patch(
        "mega_snake.light_weight.dependency_scan.handler.run_pip_audit", return_value="raw"
    ), patch(
        "mega_snake.light_weight.dependency_scan.parse_pip_audit_output", return_value=vulnerabilities
    ), patch(
        "mega_snake.light_weight.dependency_scan.handler.get_existing_issue_titles"
    ) as get_titles, patch(
        "mega_snake.light_weight.dependency_scan.handler.create_issue"
    ) as create_issue, patch(
        "mega_snake.light_weight.dependency_scan.ws_info"
    ) as ws_info:
        scan_dependencies.callback(True)
        assert ws_info.call_count == 2
        get_titles.assert_not_called()
        create_issue.assert_not_called()


def test_scan_dependencies_creates_issues_for_new_findings_only() -> None:
    """Existing findings should be skipped; only new ones create issues."""
    existing = _vuln("PYSEC-1")
    fresh = _vuln("PYSEC-2")
    with patch(
        "mega_snake.light_weight.dependency_scan.handler.export_requirements", return_value="/tmp/req.txt"
    ), patch(
        "mega_snake.light_weight.dependency_scan.handler.run_pip_audit", return_value="raw"
    ), patch(
        "mega_snake.light_weight.dependency_scan.parse_pip_audit_output", return_value=[existing, fresh]
    ), patch(
        "mega_snake.light_weight.dependency_scan.handler.get_existing_issue_titles",
        return_value={existing.issue_title},
    ), patch(
        "mega_snake.light_weight.dependency_scan.handler.create_issue"
    ) as create_issue, patch(
        "mega_snake.light_weight.dependency_scan.ws_success"
    ) as ws_success:
        scan_dependencies.callback(False)
        create_issue.assert_called_once_with(fresh.issue_title, fresh.issue_body())
        ws_success.assert_called_once()
        assert "1" in ws_success.call_args[0][0]
