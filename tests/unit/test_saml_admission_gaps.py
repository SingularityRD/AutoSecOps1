"""SAML attribute parsing, RelayState, temp cert files and email admission.

``_select_authorized_email`` runs against a real database with real
organization domains, so the domain allowlist is what PostgreSQL returns.
"""

from __future__ import annotations

import os
import uuid

import pytest
from fastapi import HTTPException
from saml2.saml import assertion_from_string
from sqlalchemy.ext.asyncio import AsyncSession

from autosecops.auth import saml
from autosecops.db.models import Organization, OrganizationDomain


def _assertion(attributes: str):
    return assertion_from_string(
        '<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">'
        f"<saml2:AttributeStatement>{attributes}</saml2:AttributeStatement>"
        "</saml2:Assertion>"
    )


@pytest.mark.parametrize(
    "attribute",
    [
        pytest.param(
            '<saml2:Attribute Name=""><saml2:AttributeValue>a@b.example'
            "</saml2:AttributeValue></saml2:Attribute>",
            id="empty_name",
        ),
        pytest.param('<saml2:Attribute Name="email"/>', id="no_value"),
    ],
)
def test_malformed_attributes_reject_the_response(attribute: str) -> None:
    with pytest.raises(HTTPException) as exc_info:
        saml.SAMLParser(_assertion(attribute)).parse_to_dict()
    assert exc_info.value.status_code == 400


def test_missing_attribute_reads_as_empty_and_parses_once() -> None:
    parser = saml.SAMLParser(
        _assertion(
            '<saml2:Attribute Name="email"><saml2:AttributeValue>'
            " user@example.com </saml2:AttributeValue></saml2:Attribute>"
        )
    )
    assert parser.get_attribute_value("department") == ""
    cached = parser.attributes
    assert parser.get_attribute_value("email") == " user@example.com "
    assert parser.attributes is cached
    # Candidates are stripped and de-duplicated.
    assert saml._extract_candidate_emails(parser) == ["user@example.com"]


def test_empty_email_value_is_never_a_candidate() -> None:
    parser = saml.SAMLParser(
        _assertion(
            '<saml2:Attribute Name="email"><saml2:AttributeValue/></saml2:Attribute>'
        )
    )
    assert saml._extract_candidate_emails(parser) == []


def test_relay_state_round_trips_organization_and_is_unpredictable() -> None:
    org_id = uuid.uuid4()
    first, second = saml.build_relay_state(org_id), saml.build_relay_state(org_id)
    assert first != second
    assert saml.parse_relay_state_org_id(first) == org_id


@pytest.mark.parametrize("relay_state", ["", ":token", "not-a-uuid:token", "abc"])
def test_relay_state_without_an_org_prefix_has_no_org(relay_state: str) -> None:
    assert saml.parse_relay_state_org_id(relay_state) is None


@pytest.mark.parametrize(
    "factory", [saml.ca_cert_tempfile, saml.metadata_cert_tempfile]
)
def test_cert_tempfiles_are_removed_after_use_and_on_error(factory) -> None:
    with factory(b"pem-bytes") as path:
        with open(path, "rb") as fh:
            assert fh.read() == b"pem-bytes"
    assert not os.path.exists(path)

    seen: list[str] = []
    with pytest.raises(RuntimeError):
        with factory(b"pem-bytes") as failing_path:
            seen.append(failing_path)
            raise RuntimeError("boom")
    assert seen and not os.path.exists(seen[0])


async def _org_with_domains(
    session: AsyncSession, *, active: str, inactive: str
) -> Organization:
    org_id = uuid.uuid4()
    org = Organization(id=org_id, name="SAML org", slug=f"saml-{org_id.hex[:12]}")
    session.add(org)
    await session.flush()
    session.add_all(
        [
            OrganizationDomain(
                organization_id=org_id,
                domain=active,
                normalized_domain=active,
                is_active=True,
            ),
            OrganizationDomain(
                organization_id=org_id,
                domain=inactive,
                normalized_domain=inactive,
                is_active=False,
            ),
        ]
    )
    await session.flush()
    return org


@pytest.mark.anyio
@pytest.mark.usefixtures("db")
async def test_email_selection_only_admits_active_org_domains(
    session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(saml, "AUTOSECOPS__AUTH_SUPERADMIN_EMAIL", None)
    suffix = uuid.uuid4().hex[:10]
    active, inactive = f"corp-{suffix}.example", f"old-{suffix}.example"
    org = await _org_with_domains(session, active=active, inactive=inactive)

    candidates = [
        "no-at-sign",
        f"user@{inactive}",  # domain was deactivated
        f"user@{active}@attacker.example",  # smuggled second @
        f"user@attacker.example?{active}",
        f"user@{active.upper()}",  # domains compare case-insensitively
        f"second@{active}",
    ]
    email, invitation = await saml._select_authorized_email(session, org.id, candidates)

    assert email == f"user@{active.upper()}"
    assert invitation is None


@pytest.mark.anyio
@pytest.mark.usefixtures("db")
async def test_email_selection_returns_none_when_no_candidate_is_admitted(
    session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(saml, "AUTOSECOPS__AUTH_SUPERADMIN_EMAIL", None)
    suffix = uuid.uuid4().hex[:10]
    org = await _org_with_domains(
        session, active=f"corp-{suffix}.example", inactive=f"old-{suffix}.example"
    )
    assert await saml._select_authorized_email(
        session, org.id, [f"user@old-{suffix}.example", "user@attacker.example"]
    ) == (None, None)
