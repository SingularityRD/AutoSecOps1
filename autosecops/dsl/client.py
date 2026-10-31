import base64

import aioboto3
from temporalio.client import Client, Plugin
from temporalio.exceptions import TemporalError
from temporalio.runtime import PrometheusConfig, Runtime, TelemetryConfig
from tenacity import (
    RetryError,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from autosecops import config
from autosecops.config import (
    TEMPORAL__API_KEY,
    TEMPORAL__API_KEY__ARN,
    TEMPORAL__CLUSTER_NAMESPACE,
    TEMPORAL__CLUSTER_URL,
    TEMPORAL__CONNECT_RETRIES,
    TEMPORAL__METRICS_HOST,
    TEMPORAL__METRICS_PORT,
    format_bind_address,
)
from autosecops.dsl._converter import get_data_converter
from autosecops.logger import logger
from autosecops.observability.otel import temporal_tracing_interceptor
from autosecops.temporal.codec import ensure_temporal_payload_encryption_ready

_client: Client | None = None
_metrics_runtime: Runtime | None = None


async def _retrieve_temporal_api_key(arn: str) -> str:
    """Retrieve the Temporal API key from AWS Secrets Manager."""
    session = aioboto3.Session()
    async with session.client(service_name="secretsmanager") as client:
        response = await client.get_secret_value(SecretId=arn)
        secret_string = response.get("SecretString")
        if not secret_string and response.get("SecretBinary"):
            secret_string = base64.b64decode(response["SecretBinary"]).decode("utf-8")
        if not secret_string:
            raise RuntimeError("Temporal API key secret is empty")
        return secret_string


@retry(
    stop=stop_after_attempt(TEMPORAL__CONNECT_RETRIES),
    wait=wait_exponential(multiplier=1, min=1, max=120),  # Up to 2 minutes
    retry=retry_if_exception_type((TemporalError, RuntimeError)),
    reraise=True,
)
async def connect_to_temporal(plugins: list[Plugin] | None = None) -> Client:
    api_key = None
    tls_config = False
    rpc_metadata = {}

    if TEMPORAL__API_KEY__ARN:
        api_key = await _retrieve_temporal_api_key(arn=TEMPORAL__API_KEY__ARN)
    elif TEMPORAL__API_KEY:
        api_key = TEMPORAL__API_KEY

    if api_key is not None:
        tls_config = True
        rpc_metadata["temporal-namespace"] = TEMPORAL__CLUSTER_NAMESPACE

    runtime = _get_metrics_runtime()
    interceptors = []
    if tracing_interceptor := temporal_tracing_interceptor():
        interceptors.append(tracing_interceptor)

    client = await Client.connect(
        target_host=TEMPORAL__CLUSTER_URL,
        namespace=TEMPORAL__CLUSTER_NAMESPACE,
        rpc_metadata=rpc_metadata,
        api_key=api_key,
        tls=tls_config,
        data_converter=get_data_converter(
            compression_enabled=config.AUTOSECOPS__CONTEXT_COMPRESSION_ENABLED
        ),
        runtime=runtime,
        plugins=plugins or [],
        interceptors=interceptors,
    )
    return client


async def get_temporal_client(plugins: list[Plugin] | None = None) -> Client:
    global _client

    if _client is not None:
        return _client

    # Outside connect_to_temporal's retry loop: a missing or malformed keyring
    # is a configuration error, so fail fast instead of retrying.
    await ensure_temporal_payload_encryption_ready()

    try:
        logger.info(
            "Connecting to Temporal server...",
            namespace=TEMPORAL__CLUSTER_NAMESPACE,
            url=TEMPORAL__CLUSTER_URL,
        )
        _client = await connect_to_temporal(plugins=plugins)
        logger.info("Successfully connected to Temporal server")
    except RetryError as e:
        msg = (
            f"Failed to connect to host {TEMPORAL__CLUSTER_URL} using namespace "
            f"{TEMPORAL__CLUSTER_NAMESPACE} after {TEMPORAL__CONNECT_RETRIES} attempts. "
        )
        raise RuntimeError(msg) from e
    else:
        return _client


def _get_metrics_runtime() -> Runtime | None:
    """Return the process-wide Prometheus runtime, creating it on first use.

    The runtime owns the exporter's listening socket, so it is created once per
    process; connection retries reuse it instead of binding the port again.
    """
    global _metrics_runtime
    if _metrics_runtime is not None or not TEMPORAL__METRICS_PORT:
        return _metrics_runtime
    try:
        port = int(TEMPORAL__METRICS_PORT)
    except ValueError:
        logger.warning(
            "Ignoring invalid TEMPORAL__METRICS_PORT; Temporal metrics are disabled",
            value=TEMPORAL__METRICS_PORT,
        )
        return None
    bind_address = format_bind_address(TEMPORAL__METRICS_HOST, port)
    logger.info("Initializing Temporal Prometheus exporter", bind_address=bind_address)
    try:
        _metrics_runtime = init_runtime_with_prometheus(bind_address=bind_address)
    except Exception as e:
        logger.warning("Failed to initialize Temporal Prometheus exporter", error=e)
    return _metrics_runtime


def init_runtime_with_prometheus(bind_address: str) -> Runtime:
    """Create a Temporal runtime that serves SDK metrics at ``bind_address``."""
    return Runtime(
        telemetry=TelemetryConfig(metrics=PrometheusConfig(bind_address=bind_address))
    )
