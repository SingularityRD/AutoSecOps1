"""Minimal Prometheus metrics with text exposition (format 0.0.4).

The API process needs a handful of counters, gauges, and histograms. This
module provides them without a third-party client library, which keeps the
dependency set unchanged and the exposition easy to audit.

Label values are caller-controlled, so every metric caps its number of label
combinations (``max_series``). Callers must still pass only bounded values,
such as route templates, never raw request paths.
"""

from __future__ import annotations

import math
import threading
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import Final, Literal

from autosecops.logger import logger

CONTENT_TYPE: Final = "text/plain; version=0.0.4; charset=utf-8"

DEFAULT_MAX_SERIES: Final = 2000
"""Label combinations one metric keeps before it drops new ones."""

type MetricType = Literal["counter", "gauge", "histogram"]
type LabelValues = tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Sample:
    """One exposition line: ``name{labels} value``."""

    name: str
    labels: tuple[tuple[str, str], ...]
    value: float


def _escape_label_value(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _escape_help(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n")


def format_value(value: float) -> str:
    """Format a sample value the way Prometheus parses it."""
    if math.isnan(value):
        return "NaN"
    if math.isinf(value):
        return "+Inf" if value > 0 else "-Inf"
    if value.is_integer() and abs(value) < 1e15:
        return str(int(value))
    return repr(value)


def _format_sample(sample: Sample) -> str:
    if not sample.labels:
        return f"{sample.name} {format_value(sample.value)}"
    labels = ",".join(
        f'{key}="{_escape_label_value(value)}"' for key, value in sample.labels
    )
    return f"{sample.name}{{{labels}}} {format_value(sample.value)}"


class Metric:
    """Base class: name, help text, label names, and a series cap."""

    type: MetricType

    def __init__(
        self,
        name: str,
        documentation: str,
        labelnames: Sequence[str] = (),
        *,
        max_series: int = DEFAULT_MAX_SERIES,
    ) -> None:
        self.name = name
        self.documentation = documentation
        self.labelnames: tuple[str, ...] = tuple(labelnames)
        self.max_series = max_series
        self._lock = threading.Lock()
        self._overflow_logged = False

    @property
    def exposition_name(self) -> str:
        """Name used in ``# HELP`` and ``# TYPE`` lines."""
        return self.name

    def _check_labels(self, labels: LabelValues) -> None:
        if len(labels) != len(self.labelnames):
            raise ValueError(
                f"{self.name} expects labels {self.labelnames}, got {len(labels)} values"
            )

    def _admit(self, known: bool, size: int) -> bool:
        """Return whether a series may be created; called with the lock held."""
        if known or size < self.max_series:
            return True
        if not self._overflow_logged:
            self._overflow_logged = True
            logger.warning(
                "Metric reached its series limit; new label values are dropped",
                metric=self.name,
                max_series=self.max_series,
            )
        return False

    def _labelled(self, labels: LabelValues) -> tuple[tuple[str, str], ...]:
        return tuple(zip(self.labelnames, labels, strict=True))

    def samples(self) -> Iterable[Sample]:
        """Return this metric's current samples."""
        raise NotImplementedError


class Counter(Metric):
    """Monotonically increasing value per label set."""

    type: MetricType = "counter"

    def __init__(
        self,
        name: str,
        documentation: str,
        labelnames: Sequence[str] = (),
        *,
        max_series: int = DEFAULT_MAX_SERIES,
    ) -> None:
        super().__init__(name, documentation, labelnames, max_series=max_series)
        self._values: dict[LabelValues, float] = {}

    @property
    def exposition_name(self) -> str:
        """Counters are exposed with the ``_total`` suffix."""
        return f"{self.name}_total"

    def inc(self, labels: LabelValues = (), amount: float = 1.0) -> None:
        """Add ``amount`` (which must not be negative) to a series."""
        if amount < 0:
            raise ValueError("Counters can only increase")
        self._check_labels(labels)
        with self._lock:
            current = self._values.get(labels)
            if self._admit(current is not None, len(self._values)):
                self._values[labels] = (current or 0.0) + amount

    def samples(self) -> Iterable[Sample]:
        """Return one ``_total`` sample per series."""
        with self._lock:
            items = list(self._values.items())
        return [
            Sample(self.exposition_name, self._labelled(labels), value)
            for labels, value in items
        ]


class Gauge(Metric):
    """Value that can go up and down per label set."""

    type: MetricType = "gauge"

    def __init__(
        self,
        name: str,
        documentation: str,
        labelnames: Sequence[str] = (),
        *,
        max_series: int = DEFAULT_MAX_SERIES,
    ) -> None:
        super().__init__(name, documentation, labelnames, max_series=max_series)
        self._values: dict[LabelValues, float] = {}

    def set(self, value: float, labels: LabelValues = ()) -> None:
        """Set a series to ``value``."""
        self._check_labels(labels)
        with self._lock:
            if self._admit(labels in self._values, len(self._values)):
                self._values[labels] = value

    def inc(self, labels: LabelValues = (), amount: float = 1.0) -> None:
        """Add ``amount`` to a series."""
        self._check_labels(labels)
        with self._lock:
            current = self._values.get(labels)
            if self._admit(current is not None, len(self._values)):
                self._values[labels] = (current or 0.0) + amount

    def dec(self, labels: LabelValues = (), amount: float = 1.0) -> None:
        """Subtract ``amount`` from a series."""
        self.inc(labels, -amount)

    def samples(self) -> Iterable[Sample]:
        """Return one sample per series."""
        with self._lock:
            items = list(self._values.items())
        return [
            Sample(self.name, self._labelled(labels), value) for labels, value in items
        ]


class CallbackMetric(Metric):
    """Gauge or counter whose series are read from ``callback`` at scrape time.

    ``name`` is used verbatim, so a counter's name must end in ``_total``.
    """

    def __init__(
        self,
        name: str,
        documentation: str,
        callback: Callable[[], Iterable[tuple[LabelValues, float]]],
        labelnames: Sequence[str] = (),
        *,
        kind: Literal["counter", "gauge"] = "gauge",
    ) -> None:
        if kind == "counter" and not name.endswith("_total"):
            raise ValueError("Counter names must end in _total")
        super().__init__(name, documentation, labelnames)
        self.type = kind
        self._callback = callback

    def samples(self) -> Iterable[Sample]:
        """Call the callback and return its series, capped at ``max_series``."""
        samples: list[Sample] = []
        for labels, value in self._callback():
            self._check_labels(labels)
            if len(samples) >= self.max_series:
                break
            samples.append(Sample(self.name, self._labelled(labels), value))
        return samples


class Histogram(Metric):
    """Cumulative bucketed observations per label set."""

    type: MetricType = "histogram"

    def __init__(
        self,
        name: str,
        documentation: str,
        labelnames: Sequence[str] = (),
        *,
        buckets: Sequence[float],
        max_series: int = DEFAULT_MAX_SERIES,
    ) -> None:
        if "le" in labelnames:
            raise ValueError("Histograms reserve the 'le' label")
        bounds = sorted(float(bound) for bound in buckets if not math.isinf(bound))
        if not bounds:
            raise ValueError("Histograms need at least one finite bucket")
        super().__init__(name, documentation, labelnames, max_series=max_series)
        self.buckets: tuple[float, ...] = (*bounds, math.inf)
        # Per series: non-cumulative bucket counts, then sum, then count.
        self._series: dict[LabelValues, list[float]] = {}

    def observe(self, value: float, labels: LabelValues = ()) -> None:
        """Record one observation."""
        self._check_labels(labels)
        if math.isnan(value):
            return
        index = next(i for i, bound in enumerate(self.buckets) if value <= bound)
        with self._lock:
            series = self._series.get(labels)
            if series is None:
                if not self._admit(False, len(self._series)):
                    return
                series = [0.0] * (len(self.buckets) + 2)
                self._series[labels] = series
            series[index] += 1
            series[-2] += value
            series[-1] += 1

    def samples(self) -> Iterable[Sample]:
        """Return cumulative ``_bucket`` samples plus ``_sum`` and ``_count``."""
        with self._lock:
            items = [(labels, list(series)) for labels, series in self._series.items()]
        samples: list[Sample] = []
        for labels, series in items:
            labelled = self._labelled(labels)
            cumulative = 0.0
            for bound, count in zip(self.buckets, series, strict=False):
                cumulative += count
                samples.append(
                    Sample(
                        f"{self.name}_bucket",
                        (*labelled, ("le", format_value(bound))),
                        cumulative,
                    )
                )
            samples.append(Sample(f"{self.name}_sum", labelled, series[-2]))
            samples.append(Sample(f"{self.name}_count", labelled, series[-1]))
        return samples


class Registry:
    """Ordered set of metrics rendered together."""

    def __init__(self) -> None:
        self._metrics: dict[str, Metric] = {}
        self._lock = threading.Lock()

    def register[M: Metric](self, metric: M) -> M:
        """Add ``metric``; names must be unique."""
        with self._lock:
            if metric.name in self._metrics:
                raise ValueError(f"Metric {metric.name} is already registered")
            self._metrics[metric.name] = metric
        return metric

    def render(self) -> str:
        """Render every metric in the Prometheus text format.

        A metric whose samples cannot be read (for example a callback that
        raises) is skipped so one failure does not empty the scrape.
        """
        with self._lock:
            metrics = list(self._metrics.values())
        lines: list[str] = []
        for metric in metrics:
            try:
                samples = list(metric.samples())
            except Exception as e:
                logger.warning(
                    "Skipping metric that failed to collect",
                    metric=metric.name,
                    error=str(e),
                )
                continue
            name = metric.exposition_name
            lines.append(f"# HELP {name} {_escape_help(metric.documentation)}")
            lines.append(f"# TYPE {name} {metric.type}")
            lines.extend(_format_sample(sample) for sample in samples)
        return "\n".join(lines) + "\n"
