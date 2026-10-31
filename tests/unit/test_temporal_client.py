from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from temporalio.client import Client
from temporalio.converter import DataConverter, DefaultFailureConverter

from autosecops import config
from autosecops.dsl import client as temporal_client
from autosecops.dsl._converter import PydanticPayloadConverter
from autosecops.temporal.codec import (
    CompositePayloadCodec,
    CompressionPayloadCodec,
    TemporalPayloadEncryptionConfigError,
)


@pytest.mark.anyio
async def test_connect_to_temporal_configures_autosecops_data_converter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connect_mock = AsyncMock(spec=Client.connect)
    monkeypatch.setattr(temporal_client.Client, "connect", connect_mock)
    monkeypatch.setattr(temporal_client, "TEMPORAL__API_KEY", None)
    monkeypatch.setattr(temporal_client, "TEMPORAL__API_KEY__ARN", None)
    monkeypatch.setattr(temporal_client, "TEMPORAL__METRICS_PORT", None)
    monkeypatch.setattr(config, "AUTOSECOPS__CONTEXT_COMPRESSION_ENABLED", True)
    monkeypatch.setattr(config, "TEMPORAL__PAYLOAD_ENCRYPTION_ENABLED", False)

    await temporal_client.connect_to_temporal()

    connect_mock.assert_awaited_once()
    connect_args = connect_mock.await_args
    assert connect_args is not None
    assert connect_args.kwargs["plugins"] == []

    converter = connect_args.kwargs["data_converter"]
    assert isinstance(converter, DataConverter)
    assert converter.payload_converter_class is PydanticPayloadConverter
    assert converter.failure_converter_class is DefaultFailureConverter

    codec = converter.payload_codec
    assert isinstance(codec, CompositePayloadCodec)
    compression_codec = codec.codecs[0]
    assert isinstance(compression_codec, CompressionPayloadCodec)
    assert compression_codec.enabled is True


@pytest.mark.anyio
async def test_get_temporal_client_fails_fast_when_encryption_has_no_keyring(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing keyring is a config error: no connect attempts, no retries."""
    connect_mock = AsyncMock(spec=Client.connect)
    monkeypatch.setattr(temporal_client.Client, "connect", connect_mock)
    monkeypatch.setattr(temporal_client, "_client", None)
    monkeypatch.setattr(config, "TEMPORAL__PAYLOAD_ENCRYPTION_ENABLED", True)
    monkeypatch.setattr(config, "TEMPORAL__PAYLOAD_ENCRYPTION_KEYRING", None)
    monkeypatch.setattr(config, "TEMPORAL__PAYLOAD_ENCRYPTION_KEYRING_ARN", None)

    with pytest.raises(TemporalPayloadEncryptionConfigError):
        await temporal_client.get_temporal_client()

    connect_mock.assert_not_awaited()
    assert temporal_client._client is None


def test_metrics_runtime_is_created_once_per_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created: list[str] = []
    runtime = object()

    def fake_init(bind_address: str) -> object:
        created.append(bind_address)
        return runtime

    monkeypatch.setattr(temporal_client, "_metrics_runtime", None)
    monkeypatch.setattr(temporal_client, "TEMPORAL__METRICS_PORT", "9090")
    monkeypatch.setattr(temporal_client, "TEMPORAL__METRICS_HOST", "::")
    monkeypatch.setattr(temporal_client, "init_runtime_with_prometheus", fake_init)

    # Connection retries must reuse the runtime, which owns the bound port.
    assert temporal_client._get_metrics_runtime() is runtime
    assert temporal_client._get_metrics_runtime() is runtime
    assert created == ["[::]:9090"]


@pytest.mark.parametrize("port", [None, "", "not-a-port"])
def test_metrics_runtime_is_disabled_without_a_valid_port(
    monkeypatch: pytest.MonkeyPatch, port: str | None
) -> None:
    monkeypatch.setattr(temporal_client, "_metrics_runtime", None)
    monkeypatch.setattr(temporal_client, "TEMPORAL__METRICS_PORT", port)
    monkeypatch.setattr(
        temporal_client,
        "init_runtime_with_prometheus",
        lambda bind_address: pytest.fail("runtime must not be created"),
    )
    assert temporal_client._get_metrics_runtime() is None
