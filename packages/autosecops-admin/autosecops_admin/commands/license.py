"""License commands."""

from __future__ import annotations

import asyncio
from typing import Annotated

import typer

from autosecops_admin.client import AdminClient, AdminClientError
from autosecops_admin.output import print_error, print_success

app = typer.Typer(no_args_is_help=True)


async def _reset_clock() -> str:
    async with AdminClient() as client:
        result = await client.reset_license_clock()
    return result.clock_high_water.isoformat()


@app.command("clock-reset")
def clock_reset(
    yes: Annotated[
        bool,
        typer.Option("--yes", "-y", help="Confirm the reset without prompting"),
    ] = False,
) -> None:
    """Reset the license clock high-water mark after a bad host clock.

    Use only after every host clock is synchronized with NTP. The API refuses
    the reset unless the recorded time is ahead of its clock, and writes a
    platform audit event for every reset.
    """
    if not yes:
        typer.confirm(
            "Reset the license clock high-water mark to the API server's"
            " current time? This is audited",
            abort=True,
        )
    try:
        high_water = asyncio.run(_reset_clock())
    except AdminClientError as e:
        print_error(str(e))
        raise typer.Exit(1) from None
    print_success(f"License clock high-water mark reset to {high_water}")
