"""
Logging configuration for K8s-Janus WebUI.
"""

import sys
import logging

# ---------------------------------------------------------------------------
# Colour formatter
# ---------------------------------------------------------------------------
_LEVEL_STYLES = {
    "DEBUG":    ("\033[36m",  "🔍"),  # cyan
    "INFO":     ("\033[32m",  "ℹ️ "),  # green
    "WARNING":  ("\033[33m",  "🚨"),  # yellow
    "ERROR":    ("\033[31m",  "❌"),  # red
    "CRITICAL": ("\033[35m",  "🔥"),  # magenta
}
_RESET  = "\033[0m"
_DIM    = "\033[2m"
_BOLD   = "\033[1m"

_LOGGER_ICONS = {
    "k8s-janus-webui":  "🌐",
    "janus.local_auth": "🔑",
    "k8s-janus.db":     "🗄️ ",
    "uvicorn":          "🦄",
    "uvicorn.error":    "🦄",
}


class _ColourFormatter(logging.Formatter):
    def __init__(self, use_color: bool = True) -> None:
        super().__init__()
        self._use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        colour, level_icon = _LEVEL_STYLES.get(record.levelname, ("", "  "))
        logger_icon = _LOGGER_ICONS.get(record.name, "  ")
        ts   = self.formatTime(record, "%Y-%m-%d %H:%M:%S")
        msg  = record.getMessage()
        if record.exc_info:
            msg += "\n" + self.formatException(record.exc_info)
        if self._use_color:
            return (
                f"{_DIM}{ts}{_RESET} "
                f"{logger_icon} {_DIM}{record.name}{_RESET} "
                f"{colour}{_BOLD}{level_icon}{_RESET} "
                f"{colour}{msg}{_RESET}"
            )
        return f"{ts} {logger_icon} {record.name} {level_icon} {msg}"


class _AccessLogFilter(logging.Filter):
    # High-frequency or low-signal paths — suppress from access log entirely
    _SUPPRESS = (
        "GET /healthz",
        "GET / ",
        "GET /admin",
        "GET /logs",
        "/api/terminal/",
        "/api/audit",
        "/api/status/",
        "/api/pods/",
        "/api/logs/",
        "/api/events/",
        "/api/system-logs/",
        "GET /namespaces/",
        "GET /static/",
        "GET /status/",
    )

    def filter(self, record):
        msg = record.getMessage()
        if any(s in msg for s in self._SUPPRESS):
            return False
        # Drop all 3xx/4xx/5xx scanner noise
        for code in (" 301 ", " 302 ", " 304 ", " 400 ", " 404 ", " 405 ", " 500 ", " 502 "):
            if code in msg:
                return False
        return True


# ---------------------------------------------------------------------------
# Apply logging config
# ---------------------------------------------------------------------------
_handler = logging.StreamHandler()
_handler.setFormatter(_ColourFormatter(use_color=sys.stderr.isatty()))
logging.root.setLevel(logging.INFO)
logging.root.handlers = [_handler]

logger = logging.getLogger("k8s-janus-webui")
logger.setLevel(logging.INFO)

logging.getLogger("uvicorn.access").addFilter(_AccessLogFilter())
logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
