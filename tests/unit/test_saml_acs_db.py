"""SAML login and ACS handling against the test database.

pysaml2 signature validation is replaced by a fake client so these tests can
drive the handler's own checks: the service gate, RelayState and request-ID
binding, one-time use of stored requests, and org admission.
"""

from __future__ import annotations

import base64
import os
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException, Request, Response
from saml2.saml import Assertion, assertion_from_string
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from autosecops.auth import saml
from autosecops.auth.types import Role
from autosecops.authz.membership import ensure_member
from autosecops.db.models import Organization, OrganizationDomain, SAMLRequestData, User

pytestmark = [pytest.mark.anyio, pytest.mark.usefixtures("db")]

REQUEST_ID = "id-" + "a" * 32


@dataclass
class FakeAuthnResponse:
    in_response_to: str | None
    assertion: Assertion | None


@dataclass
class FakeSamlClient:
    response: FakeAuthnResponse | None = None
    error: Exception | None = None
    outstanding: dict[str, str] = field(default_factory=dict)

    def parse_authn_request_response(
        self, _saml_response: str, _binding: str, *, outstanding: dict[str, str]
    ) -> FakeAuthnResponse | None:
        self.outstanding = outstanding
        if self.error is not None:
            raise self.error
        return self.response


def _assertion(email: str) -> Assertion:
    return assertion_from_string(
        '<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">'
        '<saml2:AttributeStatement><saml2:Attribute Name="email">'
        f"<saml2:AttributeValue>{email}</saml2:AttributeValue>"
        "</saml2:Attribute></saml2:AttributeStatement></saml2:Assertion>"
    )


def _request() -> Request:
    return Request(
        {"type": "http", "method": "POST", "path": "/auth/saml/acs", "headers": []}
    )


@pytest.fixture
async def org(session: AsyncSession) -> Organization:
    org_id = uuid.uuid4()
    organization = Organization(
        id=org_id, name="SAML ACS org", slug=f"saml-acs-{org_id.hex[:12]}"
    )
    session.add(organization)
    await session.flush()
    session.add(
        OrganizationDomain(
            organization_id=org_id,
            domain=f"{org_id.hex[:12]}.example",
            normalized_domain=f"{org_id.hex[:12]}.example",
            is_active=True,
        )
    )
    await session.commit()
    return organization


def _email(org: Organization, local: str = "analyst") -> str:
    return f"{local}@{org.id.hex[:12]}.example"


async def _user(
    session: AsyncSession, email: str, *, org: Organization | None, active: bool = True
) -> User:
    user = User(
        id=uuid.uuid4(),
        email=email,
        hashed_password="unused",
        is_active=active,
        is_verified=True,
    )
    session.add(user)
    await session.flush()
    if org is not None:
        await ensure_member(session, org.id, user.id)
    await session.commit()
    return user


async def _pending_login(
    session: AsyncSession,
    org: Organization,
    *,
    request_id: str = REQUEST_ID,
    expires_in: timedelta = timedelta(minutes=5),
) -> str:
    relay_state = saml.build_relay_state(org.id)
    session.add(
        SAMLRequestData(
            id=request_id,
            relay_state=relay_state,
            expires_at=datetime.now(UTC) + expires_in,
        )
    )
    await session.commit()
    return relay_state


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> FakeSamlClient:
    fake = FakeSamlClient()
    monkeypatch.setattr(
        saml, "get_org_saml_metadata_url", AsyncMock(return_value="https://idp.test")
    )
    monkeypatch.setattr(saml, "create_saml_client", AsyncMock(return_value=fake))
    monkeypatch.setattr(saml, "AUTOSECOPS__AUTH_SUPERADMIN_EMAIL", None)
    return fake


@pytest.fixture
def login_response(monkeypatch: pytest.MonkeyPatch) -> Response:
    response = Response(status_code=204)
    backend = MagicMock()
    backend.login = AsyncMock(return_value=response)
    monkeypatch.setattr(saml, "auth_backend", backend)
    return response


def _user_manager(user: User | None) -> MagicMock:
    manager = MagicMock()
    manager.saml_callback = AsyncMock(return_value=user)
    manager.on_after_login = AsyncMock()
    return manager


async def _acs(
    session: AsyncSession,
    relay_state: str,
    *,
    user_manager: MagicMock | None = None,
    service_id: str = "autosecops-ui",
) -> Response:
    return await saml.sso_acs(
        _request(),
        saml_response="PHNhbWw+",
        relay_state=relay_state,
        user_manager=user_manager or _user_manager(None),
        strategy=MagicMock(),
        db_session=session,
        role=Role(type="service", service_id=service_id),  # pyright: ignore[reportArgumentType]
    )


async def _stored(session: AsyncSession, request_id: str = REQUEST_ID) -> bool:
    session.expire_all()
    return (
        await session.scalar(
            select(SAMLRequestData.id).where(SAMLRequestData.id == request_id)
        )
    ) is not None


async def test_member_login_consumes_the_request_and_cannot_be_replayed(
    session: AsyncSession,
    org: Organization,
    client: FakeSamlClient,
    login_response: Response,
) -> None:
    user = await _user(session, _email(org), org=org)
    relay_state = await _pending_login(session, org)
    client.response = FakeAuthnResponse(REQUEST_ID, _assertion(_email(org)))
    manager = _user_manager(user)

    response = await _acs(session, relay_state, user_manager=manager)

    assert response is login_response
    assert client.outstanding == {REQUEST_ID: relay_state}
    kwargs = manager.saml_callback.await_args.kwargs
    assert kwargs["email"] == _email(org)
    assert kwargs["organization_id"] == org.id
    # Existing members log in; nobody is auto-provisioned without an invite.
    assert kwargs["allow_auto_provisioning"] is False
    manager.on_after_login.assert_awaited_once()
    assert not await _stored(session)

    with pytest.raises(HTTPException) as replay:
        await _acs(session, relay_state, user_manager=manager)
    assert replay.value.status_code == 400


async def test_only_the_ui_service_may_post_to_acs(
    session: AsyncSession, org: Organization, client: FakeSamlClient
) -> None:
    relay_state = await _pending_login(session, org)

    with pytest.raises(HTTPException) as exc_info:
        await _acs(session, relay_state, service_id="autosecops-runner")

    assert exc_info.value.status_code == 403
    assert await _stored(session)


@pytest.mark.parametrize(
    "expires_in",
    [
        pytest.param(timedelta(minutes=-1), id="expired"),
        pytest.param(None, id="unknown"),
    ],
)
async def test_unknown_or_expired_relay_state_is_rejected_before_parsing(
    session: AsyncSession,
    org: Organization,
    client: FakeSamlClient,
    expires_in: timedelta | None,
) -> None:
    if expires_in is None:
        relay_state = saml.build_relay_state(org.id)
    else:
        relay_state = await _pending_login(session, org, expires_in=expires_in)
    client.error = AssertionError("the IdP response must not be parsed")

    with pytest.raises(HTTPException) as exc_info:
        await _acs(session, relay_state)

    assert exc_info.value.status_code == 400
    assert client.outstanding == {}


async def test_rejected_response_still_purges_expired_requests(
    session: AsyncSession, org: Organization, client: FakeSamlClient
) -> None:
    relay_state = await _pending_login(session, org)
    stale_id = "id-" + "b" * 32
    await _pending_login(
        session, org, request_id=stale_id, expires_in=timedelta(minutes=-10)
    )
    client.error = ValueError("Signature verification failed")

    with pytest.raises(HTTPException) as exc_info:
        await _acs(session, relay_state)

    assert exc_info.value.status_code == 400
    assert stale_id not in client.outstanding
    assert not await _stored(session, stale_id)
    assert await _stored(session)


@pytest.mark.parametrize(
    "in_response_to",
    [None, "", "_", "short-id"],
    ids=["missing", "empty", "underscore", "too_short"],
)
async def test_malformed_in_response_to_is_rejected(
    session: AsyncSession,
    org: Organization,
    client: FakeSamlClient,
    in_response_to: str | None,
) -> None:
    relay_state = await _pending_login(session, org)
    client.response = FakeAuthnResponse(in_response_to, _assertion(_email(org)))

    with pytest.raises(HTTPException) as exc_info:
        await _acs(session, relay_state)

    assert exc_info.value.status_code == 400


async def test_response_for_another_login_is_rejected_and_burns_that_request(
    session: AsyncSession, org: Organization, client: FakeSamlClient
) -> None:
    attacker_relay = await _pending_login(session, org)
    victim_id = "id-" + "c" * 32
    await _pending_login(session, org, request_id=victim_id)
    # A response issued for the victim's request, replayed with the attacker's
    # RelayState.
    client.response = FakeAuthnResponse(victim_id, _assertion(_email(org)))

    with pytest.raises(HTTPException) as exc_info:
        await _acs(session, attacker_relay)

    assert exc_info.value.status_code == 400
    assert not await _stored(session, victim_id)


async def test_empty_parse_result_and_missing_email_are_rejected(
    session: AsyncSession, org: Organization, client: FakeSamlClient
) -> None:
    relay_state = await _pending_login(session, org)
    client.response = None
    with pytest.raises(HTTPException) as no_response:
        await _acs(session, relay_state)
    assert no_response.value.status_code == 400

    client.response = FakeAuthnResponse(REQUEST_ID, _assertion("   "))
    with pytest.raises(HTTPException) as no_email:
        await _acs(session, relay_state)
    assert no_email.value.status_code == 400


async def test_email_outside_org_domains_is_forbidden_before_user_lookup(
    session: AsyncSession, org: Organization, client: FakeSamlClient
) -> None:
    relay_state = await _pending_login(session, org)
    client.response = FakeAuthnResponse(
        REQUEST_ID, _assertion("analyst@attacker.example")
    )
    manager = _user_manager(None)

    with pytest.raises(HTTPException) as exc_info:
        await _acs(session, relay_state, user_manager=manager)

    assert exc_info.value.status_code == 403
    manager.saml_callback.assert_not_awaited()


async def test_allowlisted_user_without_membership_or_invite_is_forbidden(
    session: AsyncSession,
    org: Organization,
    client: FakeSamlClient,
    login_response: Response,
) -> None:
    other_org = Organization(
        id=uuid.uuid4(), name="Elsewhere", slug=f"elsewhere-{uuid.uuid4().hex[:8]}"
    )
    session.add(other_org)
    await session.flush()
    # A member of a different org whose email matches this org's domain.
    user = await _user(session, _email(org, "outsider"), org=other_org)
    relay_state = await _pending_login(session, org)
    client.response = FakeAuthnResponse(REQUEST_ID, _assertion(user.email))
    manager = _user_manager(user)

    with pytest.raises(HTTPException) as exc_info:
        await _acs(session, relay_state, user_manager=manager)

    assert exc_info.value.status_code == 403
    manager.on_after_login.assert_not_awaited()


async def test_inactive_user_is_rejected(
    session: AsyncSession, org: Organization, client: FakeSamlClient
) -> None:
    user = await _user(session, _email(org), org=org, active=False)
    relay_state = await _pending_login(session, org)
    client.response = FakeAuthnResponse(REQUEST_ID, _assertion(user.email))

    with pytest.raises(HTTPException) as exc_info:
        await _acs(session, relay_state, user_manager=_user_manager(user))

    assert exc_info.value.status_code == 400


async def test_login_stores_an_org_bound_request(
    session: AsyncSession, org: Organization, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = MagicMock()
    fake.prepare_for_authenticate.return_value = (
        REQUEST_ID,
        {"headers": [("Location", "https://idp.test/sso?SAMLRequest=x")]},
    )
    monkeypatch.setattr(
        saml, "get_org_saml_metadata_url", AsyncMock(return_value="https://idp.test")
    )
    monkeypatch.setattr(saml, "create_saml_client", AsyncMock(return_value=fake))

    result = await saml.login(organization_id=org.id, db_session=session)

    assert result.redirect_url == "https://idp.test/sso?SAMLRequest=x"
    relay_state = fake.prepare_for_authenticate.call_args.kwargs["relay_state"]
    assert saml.parse_relay_state_org_id(relay_state) == org.id
    stored = await session.get(SAMLRequestData, REQUEST_ID)
    assert stored is not None and stored.relay_state == relay_state
    assert stored.expires_at > datetime.now(UTC)

    fake.prepare_for_authenticate.return_value = ("id-" + "d" * 32, {"headers": []})
    with pytest.raises(HTTPException) as exc_info:
        await saml.login(organization_id=org.id, db_session=session)
    assert exc_info.value.status_code == 400


class _ClientWithoutMetadata:
    def __init__(self, _config: Any) -> None:
        self.metadata: dict[str, Any] = {}


async def test_saml_client_without_idp_metadata_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(saml, "SAML_CA_CERTS", None)
    monkeypatch.setattr(saml, "Saml2Config", MagicMock())
    monkeypatch.setattr(saml, "Saml2Client", _ClientWithoutMetadata)

    with pytest.raises(HTTPException) as exc_info:
        await saml.create_saml_client("https://idp.test/metadata")

    assert exc_info.value.status_code == 500


async def test_saml_client_config_errors_are_not_leaked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = MagicMock()
    config.return_value.load.side_effect = RuntimeError("secret internal detail")
    monkeypatch.setattr(saml, "SAML_CA_CERTS", None)
    monkeypatch.setattr(saml, "Saml2Config", config)

    with pytest.raises(HTTPException) as exc_info:
        await saml.create_saml_client("https://idp.test/metadata")

    assert exc_info.value.status_code == 400
    assert "secret" not in str(exc_info.value.detail)


async def test_saml_client_with_ca_bundle_removes_the_temp_file(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[str] = []

    class _Client:
        def __init__(self, config: Any) -> None:
            self.metadata = {"https://idp.test": object()}

    def _config() -> MagicMock:
        config = MagicMock()

        def _load(settings: dict[str, Any]) -> None:
            seen.append(settings["ca_certs"])
            assert os.path.exists(settings["ca_certs"])

        config.load.side_effect = _load
        return config

    monkeypatch.setattr(saml, "SAML_CA_CERTS", base64.b64encode(b"PEM").decode())
    monkeypatch.setattr(saml, "Saml2Config", _config)
    monkeypatch.setattr(saml, "Saml2Client", _Client)

    client = await saml.create_saml_client("https://idp.test/metadata")

    assert list(client.metadata) == ["https://idp.test"]
    assert seen and not os.path.exists(seen[0])

    # A CA-bundle failure surfaces as a configuration error, not a crash.
    monkeypatch.setattr(saml, "Saml2Client", _ClientWithoutMetadata)
    with pytest.raises(HTTPException) as exc_info:
        await saml.create_saml_client("https://idp.test/metadata")
    assert exc_info.value.status_code == 500
    assert exc_info.value.detail == "SSL certificate configuration failed"
