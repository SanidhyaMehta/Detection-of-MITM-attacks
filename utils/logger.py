## File: utils/logger.py
import logging
import os
from pathlib import Path

# Import config with error handling to avoid circular imports
try:
    from utils.config import LOGS_DIR, LOGS_FILE
except ImportError:
    # Fallback if config is not available
    BASE_DIR = Path(__file__).parent.parent
    LOGS_DIR = BASE_DIR / "logs"
    LOGS_FILE = LOGS_DIR / "logs.log"

# Ensure logs directory exists
LOGS_DIR.mkdir(parents=True, exist_ok=True)

# Configure logging settings
log_level = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, log_level, logging.INFO),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOGS_FILE),  # Save logs to a file
        logging.StreamHandler()  # Print logs to the console
    ]
)

logger = logging.getLogger(__name__)


def log_info(message):
    """Log an info message."""
    logger.info(message)


def log_error(message):
    """Log an error message."""
    logger.error(message)


def log_warning(message):
    """Log a warning message."""
    logger.warning(message)


def log_debug(message):
    """Log a debug message."""
    logger.debug(message)