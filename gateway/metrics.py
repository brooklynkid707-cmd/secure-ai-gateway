"""In-process counters exposed in Prometheus text format at ``/metrics``."""

from __future__ import annotations

import threading
from collections import defaultdict


class Metrics:
    """Labelled counters and a few gauges; safe to call from request threads."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, dict[tuple[tuple[str, str], ...], int]] = defaultdict(lambda: defaultdict(int))
        self._help: dict[str, str] = {}

    def inc(self, name: str, help_text: str = "", amount: int = 1, **labels: str) -> None:
        """Increment ``name{labels}`` by ``amount``."""
        key = tuple(sorted((k, str(v)) for k, v in labels.items()))
        with self._lock:
            self._counters[name][key] += amount
            if help_text and name not in self._help:
                self._help[name] = help_text

    def get(self, name: str, **labels: str) -> int:
        """Read one counter (0 when absent)."""
        key = tuple(sorted((k, str(v)) for k, v in labels.items()))
        with self._lock:
            return self._counters.get(name, {}).get(key, 0)

    def snapshot(self) -> dict[str, dict[str, int]]:
        """Flat dict for JSON consumers."""
        with self._lock:
            out: dict[str, dict[str, int]] = {}
            for name, series in self._counters.items():
                out[name] = {
                    ",".join(f"{k}={v}" for k, v in key) or "_": value for key, value in series.items()
                }
            return out

    def render(self) -> str:
        """Prometheus exposition text."""
        lines: list[str] = []
        with self._lock:
            for name in sorted(self._counters):
                lines.append(f"# HELP {name} {self._help.get(name, name)}")
                lines.append(f"# TYPE {name} counter")
                for key, value in sorted(self._counters[name].items()):
                    if key:
                        label_str = ",".join(f'{k}="{v}"' for k, v in key)
                        lines.append(f"{name}{{{label_str}}} {value}")
                    else:
                        lines.append(f"{name} {value}")
        return "\n".join(lines) + "\n"

    def reset(self) -> None:
        """Clear all series (tests)."""
        with self._lock:
            self._counters.clear()
