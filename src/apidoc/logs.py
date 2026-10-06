from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime

from apidoc.redact import Redactor

TRACE = 5
logging.addLevelName(TRACE, "TRACE")
LOGGER_NAME = "apidoc"
_LEVELS = {0: logging.WARNING, 1: logging.INFO, 2: logging.DEBUG, 3: TRACE}


class RedactingFilter(logging.Filter):
    def __init__(self, redactor: Redactor) -> None:
        super().__init__()
        self.redactor = redactor

    def filter(self, record: logging.LogRecord) -> bool:
        # Render the message once, redact it, and drop the raw args so no
        # handler can ever format the unredacted values again.
        record.msg = self.redactor.text(record.getMessage())
        record.args = None
        for key, value in list(vars(record).items()):
            if key.startswith("x_") and isinstance(value, str):
                setattr(record, key, self.redactor.text(value))
        return True


class JsonFormatter(logging.Formatter):
    """One JSON object per line: easy to grep, easy to ship to a log system."""

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        # Structured fields: log.info("...", extra={"x_status": 401}) -> "status": 401
        entry.update({k[2:]: v for k, v in vars(record).items() if k.startswith("x_")})
        return json.dumps(entry, default=str)


def configure(verbosity: int, json_output: bool, redactor: Redactor) -> logging.Logger:
    logger = logging.getLogger(LOGGER_NAME)
    logger.handlers.clear()
    logger.filters.clear()
    logger.setLevel(_LEVELS[min(max(verbosity, 0), 3)])
    logger.propagate = False

    handler = logging.StreamHandler(sys.stderr)  # stdout is reserved for the diagnosis
    handler.setFormatter(
        JsonFormatter() if json_output else logging.Formatter("%(levelname)-5s %(message)s")
    )
    # On the handler, not the logger: child loggers ("apidoc.runner") bypass
    # logger-level filters, but every record reaches this handler.
    handler.addFilter(RedactingFilter(redactor))
    logger.addHandler(handler)
    return logger
