"""Enable benchmark-only instrumentation before AutoSecOps imports."""

from autosecops_benchmark.pool_metrics import install_pool_metrics_instrumentation

install_pool_metrics_instrumentation()
