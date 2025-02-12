# gestor/client_handler.py
import socket
import threading
import json
import bcrypt
import sqlite3
from datetime import datetime
from .config import DB_FILE, HOST, CLIENT_PORT
from .logging import log_message
from .db import db_lock
from .replication import replicate_user
from .ring import get_responsible_node, forward_request_to_node
from .global_state import my_node_id

def process_register(message):
    username = message.get("username")
    password = message.get("password")
    public_key = message.get("public_key")
    if not username or not password or not public_key:
        return {"status": "error", "message": "Faltan campos requeridos."}
    try:
        with db_lock:
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute("""
                INSERT INTO users (username, password, ip, public_key, last_update, status)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (username, hashed, "", public_key, now_str, "disconnected"))
            conn.commit()
            conn.close()
        log_message(f"Usuario '{username}' registrado.")
        return {"status": "success", "message": "Usuario registrado exitosamente."}
    except sqlite3.IntegrityError:
        log_message(f"Registro fallido: usuario '{username}' ya existe.")
        return {"status": "error", "message": "El nombre de usuario ya existe."}
    except Exception as e:
        log_message(f"Error en register: {e}")
        return {"status": "error", "message": str(e)}

def process_login(message, addr):
    username = message.get("username")
    password = message.get("password")
    if not username or not password:
        return {"status": "error", "message": "Faltan campos requeridos."}
    try:
        with db_lock:
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute("SELECT status FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()
            if row and row[0] == "connected":
                conn.close()
                log_message(f"Login fallido: usuario '{username}' ya está conectado.")
                return {"status": "error", "message": "El usuario ya está conectado."}
            cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()
            if row and bcrypt.checkpw(password.encode(), row[0]):
                now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                cursor.execute("UPDATE users SET ip = ?, last_update = ?, status = ? WHERE username = ?",
                               (addr[0], now_str, "connected", username))
                conn.commit()
                conn.close()
                log_message(f"Usuario '{username}' autenticado desde {addr[0]}.")
                # Replicar los datos del usuario
                with db_lock:
                    conn = sqlite3.connect(DB_FILE)
                    cursor = conn.cursor()
                    cursor.execute("""
                        SELECT username, password, ip, public_key, last_update, status 
                        FROM users WHERE username = ?
                    """, (username,))
                    row = cursor.fetchone()
                    conn.close()
                if row:
                    user_record = {
                        "username": row[0],
                        "password": row[1].decode() if isinstance(row[1], bytes) else row[1],
                        "ip": row[2],
                        "public_key": row[3],
                        "last_update": row[4],
                        "status": row[5]
                    }
                    replicate_user(user_record)
                return {"status": "success", "message": "Autenticación exitosa."}
            else:
                conn.close()
                log_message(f"Login fallido: credenciales inválidas para '{username}'.")
                return {"status": "error", "message": "Credenciales inválidas."}
    except Exception as e:
        log_message(f"Error en login: {e}")
        return {"status": "error", "message": str(e)}

def process_alive_signal(message, addr):
    username = message.get("username")
    public_key = message.get("public_key")
    if not username or not public_key:
        return {"status": "error", "message": "Faltan campos requeridos."}
    try:
        with db_lock:
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
            if cursor.fetchone():
                cursor.execute("""
                    UPDATE users SET ip = ?, public_key = ?, last_update = ?, status = ?
                    WHERE username = ?
                """, (addr[0], public_key, now_str, "connected", username))
                conn.commit()
                conn.close()
                log_message(f"Alive_signal recibido para '{username}' desde {addr[0]}.")
                # Replicación opcional
                with db_lock:
                    conn = sqlite3.connect(DB_FILE)
                    cursor = conn.cursor()
                    cursor.execute("""
                        SELECT username, password, ip, public_key, last_update, status 
                        FROM users WHERE username = ?
                    """, (username,))
                    row = cursor.fetchone()
                    conn.close()
                if row:
                    user_record = {
                        "username": row[0],
                        "password": row[1].decode() if isinstance(row[1], bytes) else row[1],
                        "ip": row[2],
                        "public_key": row[3],
                        "last_update": row[4],
                        "status": row[5]
                    }
                    replicate_user(user_record)
                return {"status": "success", "message": "Señal de vida actualizada."}
            else:
                conn.close()
                log_message(f"Alive_signal fallido: usuario '{username}' no registrado.")
                return {"status": "error", "message": "Usuario no registrado."}
    except Exception as e:
        log_message(f"Error en alive_signal: {e}")
        return {"status": "error", "message": str(e)}

def process_get_user(message):
    requester = message.get("username")
    target = message.get("target_username")
    if not requester or not target:
        return {"status": "error", "message": "Faltan campos requeridos."}
    try:
        with db_lock:
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute("SELECT ip, public_key, last_update, status FROM users WHERE username = ?", (target,))
            row = cursor.fetchone()
            conn.close()
        if row:
            ip, public_key, last_update, status = row
            if status != "connected":
                log_message(f"get_user: '{target}' está desconectado (solicitado por '{requester}').")
                return {"status": "error", "message": "El usuario está desconectado."}
            log_message(f"Información de '{target}' enviada a '{requester}'.")
            return {"status": "success", "ip": ip, "public_key": public_key}
        else:
            log_message(f"get_user: usuario '{target}' no encontrado (solicitado por '{requester}').")
            return {"status": "error", "message": "Usuario no encontrado."}
    except Exception as e:
        log_message(f"Error en get_user: {e}")
        return {"status": "error", "message": str(e)}

def process_client_message(message, addr):
    action = message.get("action")
    if action == "register":
        return process_register(message)
    elif action == "login":
        return process_login(message, addr)
    elif action == "alive_signal":
        return process_alive_signal(message, addr)
    elif action == "get_user":
        return process_get_user(message)
    else:
        log_message(f"Acción no reconocida en petición de cliente: {action}")
        return {"status": "error", "message": "Acción no reconocida."}

def handle_client(conn, addr, initial_managers):
    try:
        data = conn.recv(4096)
        if not data:
            return
        message = json.loads(data.decode())
        username = message.get("username")
        if username:
            # Se consulta cuál es el nodo responsable para el usuario
            responsible = get_responsible_node(username, initial_managers)
            if responsible.get("node_id") == my_node_id:
                response = process_client_message(message, addr)
            else:
                response = forward_request_to_node(responsible, message)
        else:
            response = {"status": "error", "message": "Username no proporcionado."}
        conn.sendall(json.dumps(response).encode())
    except Exception as e:
        log_message(f"Error en handle_client: {e}")
    finally:
        conn.close()

def client_server(initial_managers):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, CLIENT_PORT))
    s.listen()
    log_message(f"Servidor para clientes iniciado en {HOST}:{CLIENT_PORT}")
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_client, args=(conn, addr, initial_managers), daemon=True).start()
