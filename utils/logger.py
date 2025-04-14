## File: utils/logger.py
import logging

# Configure logging settings
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("logs.log"),  # Save logs to a file
        logging.StreamHandler()  # Print logs to the console
    ]
)

def log_info(message):
    logging.info(message)

def log_error(message):
    logging.error(message)