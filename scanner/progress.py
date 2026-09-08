import math
import time
from typing import Callable, Optional, TextIO


class ProgressReporter:
    """Write secret-safe, line-oriented progress messages to a text stream."""

    def __init__(
        self,
        stream: TextIO,
        clock: Optional[Callable[[], float]] = None,
    ) -> None:
        self.stream = stream
        self._clock = clock or time.monotonic
        self._started_at = self._clock()
        self._disabled = False

    def __call__(self, message: str) -> None:
        if self._disabled:
            return
        elapsed = max(0.0, self._clock() - self._started_at)
        try:
            self.stream.write(
                f"[confluleaks +{_format_elapsed(elapsed)}] {message}\n"
            )
            self.stream.flush()
        except (OSError, UnicodeError):
            self._disabled = True


def _format_elapsed(seconds: float) -> str:
    if not math.isfinite(seconds) or seconds < 0:
        seconds = 0
    total_seconds = int(seconds)
    hours, remainder = divmod(total_seconds, 3_600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
