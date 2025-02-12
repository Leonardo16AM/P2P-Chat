# gestor/server_handler.py
import socket
import threading
import json
from .logging import log_message
from .client_handler import process_client_message
from .replication import update_local_user
from .ring import update_initial_managers

def handle_server_connection(conn, addr):
    try:
        data = conn.recv(4096)
        if not data:
            return
        message = json.loads(data.decode())
        action = message.get("action")
        if action == "forward_request":
            original_message = message.get("original_message")
            response = process_client_message(original_message, addr)
            conn.sendall(json.dumps(response).encode())
        elif action == "replicate_user":
            user_record = message.get("user_record")
            update_local_user(user_record)
            conn.sendall(json.dumps({"status": "success", "message": "Réplica aplicada"}).encode())
        elif action == "ring_update":
            sender_info = {
                "node_id": int(message.get("node_id")),
                "ip": message.get("ip"),
                "server_port": message.get("server_port"),
                "last_modified": float(message.get("timestamp"))
            }
            update_initial_managers(sender_info)
            conn.sendall(json.dumps({"status": "success"}).encode())
        elif action == "alive_check":
            conn.sendall(json.dumps({"status": "alive"}).encode())
        else:
            conn.sendall(json.dumps({"status": "error", "message": "Acción desconocida en comunicación servidor"}).encode())
    except Exception as e:
        log_message(f"Error en handle_server_connection: {e}")
    finally:
        conn.close()

def server_server():
    from .config import HOST, SERVER_PORT
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, SERVER_PORT))
    s.listen()
    log_message(f"Servidor entre gestores iniciado en {HOST}:{SERVER_PORT}")
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_server_connection, args=(conn, addr), daemon=True).start()
