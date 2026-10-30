"""CORS defaults must not let arbitrary sites make credentialed requests."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.testclient import TestClient

from autosecops.api.app import CORSPolicy, resolve_cors_policy

_EVIL_ORIGIN = "https://attacker.example"


def _me() -> dict[str, str]:
    return {"email": "member@example.com"}


def _client(policy: CORSPolicy) -> TestClient:
    app = FastAPI()
    app.add_api_route("/me", _me, methods=["GET"])
    app.add_middleware(
        CORSMiddleware,
        allow_origins=policy.allow_origins,
        allow_credentials=policy.allow_credentials,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    return TestClient(app)


def test_unset_allow_origins_defaults_to_the_app_origin() -> None:
    policy = resolve_cors_policy(None, "https://autosecops.example.com/some/path")

    assert policy == CORSPolicy(
        allow_origins=["https://autosecops.example.com"], allow_credentials=True
    )


def test_unset_allow_origins_does_not_reflect_foreign_origins() -> None:
    """Starlette echoes any Origin for a credentialed wildcard."""
    client = _client(resolve_cors_policy(None, "https://autosecops.example.com"))

    response = client.get(
        "/me", headers={"Origin": _EVIL_ORIGIN, "Cookie": "session=1"}
    )
    preflight = client.options(
        "/me",
        headers={"Origin": _EVIL_ORIGIN, "Access-Control-Request-Method": "POST"},
    )

    assert response.headers.get("access-control-allow-origin") != _EVIL_ORIGIN
    assert preflight.headers.get("access-control-allow-origin") != _EVIL_ORIGIN


def test_explicit_wildcard_never_allows_credentials() -> None:
    policy = resolve_cors_policy("*", "https://autosecops.example.com")
    client = _client(policy)

    response = client.get(
        "/me", headers={"Origin": _EVIL_ORIGIN, "Cookie": "session=1"}
    )

    assert policy.allow_credentials is False
    assert response.headers.get("access-control-allow-origin") == "*"
    assert "access-control-allow-credentials" not in response.headers


def test_explicit_origins_are_trimmed_and_keep_credentials() -> None:
    policy = resolve_cors_policy(
        " http://localhost:3000 , https://autosecops.example.com,,",
        "https://ignored.example",
    )

    assert policy == CORSPolicy(
        allow_origins=["http://localhost:3000", "https://autosecops.example.com"],
        allow_credentials=True,
    )
