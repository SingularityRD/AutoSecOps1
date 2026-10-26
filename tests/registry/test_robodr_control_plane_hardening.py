"""Transport hardening of `tools.robodr` (SPKI pins, client keys, HTTP parsing)."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import ssl
import tempfile
from pathlib import Path
from typing import Any

import pytest
from autosecops_registry import config as registry_config
from autosecops_registry.integrations import robodr_control_plane as cp
from autosecops_registry.integrations import robodr_evidence as ev
from autosecops_registry.sdk.robot_edr import RobotEdrClient
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

VECTORS = Path(__file__).parents[1] / "data" / "robodr_control_plane_v2"

# --------------------------------------------------------------------------- #
# DER helpers (test-only re-encoding of a certificate's SPKI)
# --------------------------------------------------------------------------- #


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _children(data: bytes) -> list[bytes]:
    out, pos = [], 0
    while pos < len(data):
        _, start, end = cp._der_element(data, pos)  # pyright: ignore[reportPrivateUsage]
        out.append(data[pos:end])
        pos = end
        del start
    return out


def _seq(items: list[bytes]) -> bytes:
    body = b"".join(items)
    return b"\x30" + _der_len(len(body)) + body


def _contents(element: bytes) -> bytes:
    _, start, end = cp._der_element(element, 0)  # pyright: ignore[reportPrivateUsage]
    return element[start:end]


def _self_signed() -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ugv-x")])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return cert, key


def _with_compressed_point(cert: x509.Certificate) -> tuple[bytes, bytes]:
    """The certificate's DER with its EC point compressed, and that SPKI."""
    public = cert.public_key()
    assert isinstance(public, ec.EllipticCurvePublicKey)
    uncompressed_spki = public.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    algorithm, _bits = _children(_contents(uncompressed_spki))
    point = public.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint
    )
    bit_string = b"\x03" + _der_len(len(point) + 1) + b"\x00" + point
    spki = _seq([algorithm, bit_string])
    tbs, sig_alg, sig = _children(
        _contents(cert.public_bytes(serialization.Encoding.DER))
    )
    fields = _children(_contents(tbs))
    index = fields.index(uncompressed_spki)
    fields[index] = spki
    return _seq([_seq(fields), sig_alg, sig]), spki


def test_spki_pin_hashes_the_raw_spki_of_the_certificate() -> None:
    cert, _ = _self_signed()
    der = cert.public_bytes(serialization.Encoding.DER)
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    assert cp.certificate_spki(der) == spki
    assert cp.spki_sha256(der) == hashlib.sha256(spki).hexdigest()


def test_spki_pin_of_a_compressed_point_certificate_is_not_re_encoded() -> None:
    cert, _ = _self_signed()
    der, compressed_spki = _with_compressed_point(cert)
    reencoded = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    assert len(compressed_spki) < len(reencoded)
    # robodr-agentd (webpki) pins the bytes as they are in the certificate.
    assert cp.spki_sha256(der) == hashlib.sha256(compressed_spki).hexdigest()
    assert cp.spki_sha256(der) != hashlib.sha256(reencoded).hexdigest()


@pytest.mark.parametrize(
    "der", [b"", b"\x30\x03\x02\x01\x01", b"\x04\x00", b"\x30\x81"]
)
def test_spki_of_a_non_certificate_is_refused(der: bytes) -> None:
    with pytest.raises(ValueError):
        cp.spki_sha256(der)


# --------------------------------------------------------------------------- #
# SOC client key: never a named file when memfd is available
# --------------------------------------------------------------------------- #


def _identity() -> tuple[str, str]:
    cert, key = _self_signed()
    return (
        cert.public_bytes(serialization.Encoding.PEM).decode(),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode(),
    )


@pytest.mark.skipif(not hasattr(os, "memfd_create"), reason="Linux memfd only")
def test_client_key_is_loaded_from_anonymous_memory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def no_files(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("the client key must not touch the file system")

    monkeypatch.setattr(tempfile, "TemporaryDirectory", no_files)
    monkeypatch.setattr(tempfile, "mkdtemp", no_files)
    before = set(os.listdir("/proc/self/fd"))
    cert_pem, key_pem = _identity()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    cp._load_client_identity(context, cert_pem, key_pem)  # pyright: ignore[reportPrivateUsage]
    assert set(os.listdir("/proc/self/fd")) <= before | {str(fd) for fd in range(3)}


def test_client_key_falls_back_to_a_private_directory_removed_after_use(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def no_memfd(*args: Any, **kwargs: Any) -> int:
        raise OSError("memfd_create unavailable")

    monkeypatch.setattr(os, "memfd_create", no_memfd, raising=False)
    seen: list[tuple[str, int]] = []
    real = tempfile.TemporaryDirectory

    class Recording(real):  # type: ignore[valid-type, misc]
        def __enter__(self) -> str:
            path = super().__enter__()
            seen.append((path, os.stat(path).st_mode & 0o777))
            return path

    monkeypatch.setattr(tempfile, "TemporaryDirectory", Recording)
    cert_pem, key_pem = _identity()
    cp._load_client_identity(ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT), cert_pem, key_pem)  # pyright: ignore[reportPrivateUsage]
    ((path, mode),) = seen
    assert mode == 0o700
    assert not Path(path).exists()


def test_a_bad_client_identity_is_reported_without_leaving_files() -> None:
    cert_pem, _ = _identity()
    _, other_key = _identity()
    with pytest.raises(ValueError, match="do not load"):
        cp._load_client_identity(  # pyright: ignore[reportPrivateUsage]
            ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT), cert_pem, other_key
        )


# --------------------------------------------------------------------------- #
# HTTP answers: ASCII digits only
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "raw",
    [
        b"HTTP/1.1 2\xb20 OK\r\n\r\n",  # latin-1 superscript two
        b"HTTP/1.1 +20 OK\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: \xb2\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: +1\r\n\r\nx",
        b"HTTP/1.1 200 OK\r\nContent-Length: 1_0\r\n\r\nx",
    ],
)
def test_non_ascii_digits_are_a_control_plane_error(raw: bytes) -> None:
    with pytest.raises(cp.ControlPlaneError):
        cp.parse_answer(raw, max_body=1024)


def test_ascii_uint() -> None:
    assert cp._ascii_uint("30") == 30  # pyright: ignore[reportPrivateUsage]
    for text in (None, "", "²", "٣", "3 ", "-1", "1" * 19):
        assert cp._ascii_uint(text) is None  # pyright: ignore[reportPrivateUsage]


# --------------------------------------------------------------------------- #
# Platform limits and SDK paths
# --------------------------------------------------------------------------- #


def test_stored_bundle_cap_follows_the_platform_setting() -> None:
    from autosecops import config as platform_config

    assert cp.MAX_STORED_BUNDLE_BYTES == min(
        registry_config.TRACECAT__ROBOT_EDR_MAX_EVIDENCE_BYTES, 256 * 1024 * 1024
    )
    assert (
        registry_config.TRACECAT__ROBOT_EDR_MAX_EVIDENCE_BYTES
        == platform_config.TRACECAT__ROBOT_EDR_MAX_EVIDENCE_BYTES
    )


def test_a_manifest_over_the_robots_largest_export_is_refused() -> None:
    """The robot exports at most 256 MiB (`max_export_bytes`, §11.7)."""
    assert ev.MAX_EXPORT_BYTES == 256 * 1024 * 1024
    manifest = json.loads((VECTORS / "evidence" / "manifest.json").read_bytes())
    bundle = manifest["bundle"]
    size = ev.MAX_EXPORT_BYTES + 1
    bundle["bytes"] = size
    bundle["chunk_bytes"] = ev.MAX_CHUNK_BYTES
    count = -(-size // ev.MAX_CHUNK_BYTES)
    bundle["chunks"] = [
        {
            "index": i,
            "offset": i * ev.MAX_CHUNK_BYTES,
            "bytes": min(ev.MAX_CHUNK_BYTES, size - i * ev.MAX_CHUNK_BYTES),
            "sha256": "0" * 64,
        }
        for i in range(count)
    ]
    with pytest.raises(ev.EvidenceError, match="256 MiB"):
        ev.parse_manifest(
            json.dumps(manifest).encode(),
            robot_id=manifest["robot_id"],
            export_id=manifest["export_id"],
        )


@pytest.mark.anyio
async def test_store_evidence_percent_encodes_the_case_id() -> None:
    paths: list[str] = []

    class Client:
        async def post(self, path: str, **kwargs: Any) -> dict[str, Any]:
            paths.append(path)
            return {}

    sdk = RobotEdrClient(Client())  # type: ignore[arg-type]
    await sdk.store_evidence(
        "../../workspaces/x",
        robot_id="ugv-x",
        export_id="e",
        manifest_base64="",
        manifest_signature="",
        bundle_base64="",
        verification={},
    )
    assert paths == ["/robot-edr/cases/..%2F..%2Fworkspaces%2Fx/evidence"]
