# gestor/logging.py
from datetime import datetime
from .config import LOG_FILE


def log_message(message: str) -> None:
    """
    Logs a message to the log file and prints it to the console.
    """
    log_entry = f"{datetime.now()} - {message}\n"
    with open(LOG_FILE, "a") as f:
        f.write(log_entry)
    print(log_entry, end="")
