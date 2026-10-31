"""Mock tests for license commands."""

from __future__ import annotations

import respx
from autosecops_admin.cli import app
from httpx import Response
from typer.testing import CliRunner

from .conftest import API_URL

runner = CliRunner()


@respx.mock
def test_clock_reset_success(mock_env: None) -> None:
    route = respx.post(f"{API_URL}/admin/license/clock/reset").mock(
        return_value=Response(
            200, json={"clock_high_water": "2026-06-01T00:00:00+00:00"}
        )
    )

    result = runner.invoke(app, ["license", "clock-reset", "--yes"])

    assert result.exit_code == 0, result.output
    assert route.called
    assert "2026-06-01T00:00:00+00:00" in result.output


@respx.mock
def test_clock_reset_refused(mock_env: None) -> None:
    respx.post(f"{API_URL}/admin/license/clock/reset").mock(
        return_value=Response(409, json={"detail": "nothing to reset"})
    )

    result = runner.invoke(app, ["license", "clock-reset", "--yes"])

    assert result.exit_code == 1
    assert "nothing to reset" in result.output


def test_clock_reset_asks_for_confirmation(mock_env: None) -> None:
    result = runner.invoke(app, ["license", "clock-reset"], input="n\n")

    assert result.exit_code == 1
