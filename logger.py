# logger.py
import logging
import sys

LOG_FILE = "/var/log/asimily_wizard.log"

def setup_logger() -> logging.Logger:
    logger = logging.getLogger("asimily_wizard")
    logger.setLevel(logging.DEBUG)

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    # Try to write to log file; fall back to /tmp if /var/log not writable
    try:
        fh = logging.FileHandler(LOG_FILE)
    except PermissionError:
        fh = logging.FileHandler("/tmp/asimily_wizard.log")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)

    sh = logging.StreamHandler(sys.stderr)
    sh.setLevel(logging.WARNING)
    sh.setFormatter(fmt)

    if not logger.handlers:
        logger.addHandler(fh)
        logger.addHandler(sh)
    return logger

log = setup_logger()
