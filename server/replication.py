# gestor/replication.py
import socket
import json
import random
from .logging import log_message
from .config import SERVER_PORT
from .global_state import initial_managers, my_node_id

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
    # Actualiza (o inserta) en la base de datos local el registro replicado
    import sqlite3
    from datetime import datetime
    from .config import DB_FILE
    try:
        username = user_record.get("username")
        new_time = datetime.strptime(user_record.get("last_update"), "%Y-%m-%d %H:%M:%S")
    except Exception:
        new_time = datetime.now()
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT last_update FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        if row:
            old_time = datetime.strptime(row[0], "%Y-%m-%d %H:%M:%S")
            if new_time > old_time:
                cursor.execute("""
                    UPDATE users SET password = ?, ip = ?, public_key = ?, last_update = ?, status = ?
                    WHERE username = ?
                """, (user_record.get("password"), user_record.get("ip"),
                      user_record.get("public_key"), user_record.get("last_update"),
                      user_record.get("status"), username))
                log_message(f"Registro de usuario '{username}' actualizado por réplica.")
        else:
            cursor.execute("""
                INSERT INTO users (username, password, ip, public_key, last_update, status)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (username, user_record.get("password"), user_record.get("ip"),
                  user_record.get("public_key"), user_record.get("last_update"),
                  user_record.get("status")))
            log_message(f"Registro de usuario '{username}' insertado por réplica.")
        conn.commit()
        conn.close()
    except Exception as e:
        log_message(f"Error actualizando usuario local por réplica: {e}")
