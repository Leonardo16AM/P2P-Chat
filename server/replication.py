import socket
import json
import random
import sqlite3
from .logging import log_message
from .config import SERVER_PORT, DB_FILE
from .global_state import initial_managers, my_node_id
from .db import db_lock

def replicate_user(user_record):
    # Selecciona de forma aleatoria entre los nodos disponibles (excluyendo el propio)
    nodes = [info for nid, info in initial_managers.items() if nid != my_node_id]
    replication_factor = min(len(nodes), 3)
    if replication_factor <= 0:
        log_message("No hay nodos disponibles para replicación.")
        return
    selected_nodes = random.sample(nodes, replication_factor)
    for node in selected_nodes:
        msg = {"action": "replicate_user", "user_record": user_record}
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((node["ip"], node["server_port"]))
                s.sendall(json.dumps(msg).encode())
                log_message(f"Enviada réplica de usuario '{user_record.get('username')}' a nodo {node.get('node_id')}.")
        except Exception as e:
            log_message(f"Error replicando usuario a nodo {node.get('node_id')}: {e}")

def update_local_user(user_record):
    """
    Actualiza (o inserta) en la base de datos local el registro replicado.
    Si el usuario ya existe, se actualizan sus datos; de lo contrario, se inserta un nuevo registro.
    """
    try:
        with db_lock:
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute("SELECT username FROM users WHERE username = ?", (user_record["username"],))
            existing = cursor.fetchone()
            if existing:
                cursor.execute("""
                    UPDATE users
                    SET password = ?, ip = ?, public_key = ?, last_update = ?, status = ?
                    WHERE username = ?
                """, (
                    user_record["password"],
                    user_record["ip"],
                    user_record["public_key"],
                    user_record["last_update"],
                    user_record["status"],
                    user_record["username"]
                ))
            else:
                cursor.execute("""
                    INSERT INTO users (username, password, ip, public_key, last_update, status)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    user_record["username"],
                    user_record["password"],
                    user_record["ip"],
                    user_record["public_key"],
                    user_record["last_update"],
                    user_record["status"]
                ))
            conn.commit()
            conn.close()
        log_message(f"Usuario replicado '{user_record.get('username')}' actualizado en nodo {my_node_id}.")
    except Exception as e:
        log_message(f"Error actualizando usuario replicado '{user_record.get('username')}': {e}")