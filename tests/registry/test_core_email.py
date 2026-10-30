"""Tests for the `core.send_email_smtp` message builder."""

from email.utils import parsedate_to_datetime

import pytest
from autosecops_registry.core.email import _build_email_message


def _build(**overrides: object):
    kwargs: dict[str, object] = {
        "sender": "alerts@mail.example.com",
        "recipients": ["soc@example.com"],
        "subject": "Alert",
        "body": "Severity: high",
        "content_type": "text/plain",
    }
    kwargs.update(overrides)
    return _build_email_message(**kwargs)  # pyright: ignore[reportArgumentType]


def test_message_carries_date_and_message_id() -> None:
    """RFC 5322 requires Date, and relays such as Gmail reject mail without a
    Message-ID. smtplib's send_message adds neither."""
    first = _build()
    second = _build()

    for msg in (first, second):
        assert parsedate_to_datetime(msg["Date"]).tzinfo is not None
        assert msg["Message-ID"].endswith("@mail.example.com>")
    assert first["Message-ID"] != second["Message-ID"]


def test_caller_supplied_date_and_message_id_are_kept_once() -> None:
    msg = _build(
        headers={
            "message-id": "<thread-1@example.com>",
            "Date": "Mon, 01 Jan 2024 00:00:00 +0000",
        }
    )

    assert msg.get_all("Message-ID") == ["<thread-1@example.com>"]
    assert msg.get_all("Date") == ["Mon, 01 Jan 2024 00:00:00 +0000"]


def test_html_body_is_sanitized_with_a_plaintext_alternative() -> None:
    msg = _build(
        content_type="text/html",
        body="<b>hi</b><script>alert(1)</script>",
        plaintext_alternative="hi",
    )

    parts = {part.get_content_type(): part for part in msg.iter_parts()}
    html = parts["text/html"].get_content()
    assert "<b>hi</b>" in html
    assert "script" not in html
    assert parts["text/plain"].get_content().strip() == "hi"


@pytest.mark.parametrize(
    ("sender", "recipients"),
    [
        ("alerts@example.com\r\nBcc: attacker@example.com", ["soc@example.com"]),
        ("alerts@example.com", ["soc@example.com", "not an address"]),
    ],
)
def test_invalid_addresses_are_rejected(sender: str, recipients: list[str]) -> None:
    with pytest.raises(ValueError):
        _build(sender=sender, recipients=recipients)
