"""Tests for dependency_scan_handler.py"""

from typing import Generator
from unittest.mock import patch, MagicMock
import pytest
from mega_snake.light_weight.dependency_scan_handler import (
    export_requirements,
    run_pip_audit,
    get_existing_issue_titles,
    create_issue,
)


@pytest.fixture(name="run_operation")
def fixture_run_operation() -> Generator[MagicMock, None, None]:
    """Mock run_operation"""
    with patch("mega_snake.light_weight.dependency_scan_handler.run_operation") as mock:
        yield mock


def test_export_requirements(run_operation: MagicMock) -> None:
    """Test export_requirements builds and runs the uv export command"""
    run_operation.return_value = MagicMock()
    path = export_requirements()
    run_operation.assert_called_once()
    command: str = run_operation.call_args[0][0]
    assert "uv export --no-hashes --format requirements-txt -o" in command
    assert path in command


def test_run_pip_audit(run_operation: MagicMock) -> None:
    """Test run_pip_audit builds the pip-audit command and does not raise on non-zero exit"""
    run_operation.return_value = MagicMock(stdout=" {} \n")
    result = run_pip_audit("/tmp/requirements.txt")
    run_operation.assert_called_once()
    command: str = run_operation.call_args[0][0]
    kwargs = run_operation.call_args[1]
    assert "pip-audit -r /tmp/requirements.txt --format json" in command
    assert kwargs.get("check") is False
    assert result == "{}"


def test_get_existing_issue_titles_empty(run_operation: MagicMock) -> None:
    """Test get_existing_issue_titles returns an empty set when gh returns nothing"""
    run_operation.return_value = MagicMock(stdout="   ")
    assert get_existing_issue_titles() == set()
    command: str = run_operation.call_args[0][0]
    assert "gh issue list --state all --search" in command
    assert "[dependency-scan] in:title" in command


def test_get_existing_issue_titles_parses_json(run_operation: MagicMock) -> None:
    """Test get_existing_issue_titles parses the JSON output from gh into a set of titles"""
    run_operation.return_value = MagicMock(stdout='[{"title": "A"}, {"title": "B"}]')
    assert get_existing_issue_titles() == {"A", "B"}


def test_create_issue(run_operation: MagicMock, tmp_path, monkeypatch) -> None:
    """Test create_issue writes the body to a temp file and invokes gh issue create"""
    monkeypatch.setattr("tempfile.gettempdir", lambda: str(tmp_path))
    run_operation.return_value = MagicMock()
    create_issue("My Title", "My Body")
    run_operation.assert_called_once()
    command: str = run_operation.call_args[0][0]
    assert 'gh issue create --title "My Title" --body-file' in command
    body_file = tmp_path / "mega_snake_dependency_scan_issue_body.md"
    assert body_file.read_text(encoding="utf-8") == "My Body"
