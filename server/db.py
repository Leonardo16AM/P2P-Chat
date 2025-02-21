# gestor/db.py
import sqlite3
from threading import Lock
from datetime import datetime
from .config import DB_FILE
from .logging import log_message
import server.global_state as gs

db_lock = Lock()


def init_db() -> None:
    """
    Initializes the SQLite database by creating the necessary tables.
    """

    with db_lock:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password BLOB NOT NULL,
                ip TEXT NOT NULL,
                public_key TEXT NOT NULL,
                last_update TEXT NOT NULL,
                status TEXT NOT NULL
            )
        """
        )
        conn.commit()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS backups (
                username TEXT PRIMARY KEY,
                password BLOB NOT NULL,
                ip TEXT NOT NULL,
                public_key TEXT NOT NULL,
                last_update TEXT NOT NULL,
                status TEXT NOT NULL,
                node_id TEXT NOT NULL
            )
        """
        )
        conn.commit()
        conn.close()
    log_message("Base de datos inicializada.")


#region del_db
def del_db():
    with gs.db_lock:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute(
                """
                    DELETE FROM users
                    WHERE 1 = 1;
                """
                )
        cursor.execute(
                """
                    DELETE FROM backups
                    WHERE 1 = 1;
                """
                )
        conn.commit()
        conn.close()
