"""APIdoc: diagnose failing API calls."""

import logging

__version__ = "0.1.0"

# Library convention: emit nothing unless the application (our CLI) configures
# logging. Without this, Python's last-resort handler prints warnings to stderr.
logging.getLogger("apidoc").addHandler(logging.NullHandler())
