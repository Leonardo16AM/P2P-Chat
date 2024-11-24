import socket
import threading
import sqlite3
import json
import bcrypt
import time
from datetime import datetime, timedelta

# Configuración
HOST = '0.0.0.0'  # Escuchar en todas las interfaces
PORT = 65432      # Puerto a usar
ALIVE_INTERVAL = 10  # Intervalo de alive_signal en segundos
TIMEOUT = 60         # Tiempo antes de considerar a un usuario como desconectado
LOG_FILE = 'gestor.log'

def init_db():
    conn = sqlite3.connect('chat_manager.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password BLOB NOT NULL,
            ip TEXT NOT NULL,
            public_key TEXT NOT NULL,
            last_seen TIMESTAMP NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def log_message(message):
    with open(LOG_FILE, 'a') as log_file:
        log_file.write(f"{datetime.now()} - {message}\n")

def handle_client(conn, addr):
    log_message(f"Conexión establecida desde {addr}")
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            try:
                message = json.loads(data.decode())
                response = process_message(message, addr)
            except json.JSONDecodeError:
                response = {"status": "error", "message": "Formato JSON inválido."}
            conn.sendall(json.dumps(response).encode())
    except ConnectionResetError:
        log_message(f"Conexión perdida con {addr}")
    finally:
        conn.close()

def process_message(message, addr):
    action = message.get("action")
    if action == "register":
        return register_user(message)
    elif action == "login":
        return login_user(message, addr)
    elif action == "alive_signal":
        return alive_signal(message, addr)
    elif action == "get_user":
        return get_user_info(message)
    else:
        return {"status": "error", "message": "Acción no reconocida."}

#region register
def register_user(message):
    username = message.get("username")
    password = message.get("password")
    public_key = message.get("public_key")

    if not username or not password or not public_key:
        return {"status": "error", "message": "Faltan campos requeridos."}

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    try:
        conn = sqlite3.connect('chat_manager.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password, ip, public_key, last_seen) VALUES (?, ?, ?, ?, ?)",
                       (username, hashed, "", public_key, datetime.now()))
        conn.commit()
        conn.close()
        log_message(f"Usuario {username} registrado exitosamente.")
        return {"status": "success", "message": "Usuario registrado exitosamente."}
    except sqlite3.IntegrityError:
        log_message(f"Error: El nombre de usuario {username} ya existe.")
        return {"status": "error", "message": "El nombre de usuario ya existe."}
    except Exception as e:
        log_message(f"Error en el servidor durante el registro de {username}: {str(e)}")
        return {"status": "error", "message": f"Error en el servidor: {str(e)}"}

#region login
def login_user(message, addr):
    username = message.get("username")
    password = message.get("password")

    if not username or not password:
        return {"status": "error", "message": "Faltan campos requeridos."}

    try:
        conn = sqlite3.connect('chat_manager.db')
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        if row and bcrypt.checkpw(password.encode(), row[0]):
            cursor.execute("UPDATE users SET ip = ?, last_seen = ? WHERE username = ?",
                           (addr[0], datetime.now(), username))
            conn.commit()
            conn.close()
            log_message(f"Usuario {username} autenticado exitosamente desde {addr[0]}.")
            return {"status": "success", "message": "Autenticación exitosa."}
        else:
            conn.close()
            log_message(f"Error: Credenciales inválidas para {username}.")
            return {"status": "error", "message": "Credenciales inválidas."}
    except Exception as e:
        log_message(f"Error en el servidor durante el inicio de sesión de {username}: {str(e)}")
        return {"status": "error", "message": f"Error en el servidor: {str(e)}"}

#region alive
def alive_signal(message, addr):
    username = message.get("username")
    public_key = message.get("public_key")

    if not username or not public_key:
        return {"status": "error", "message": "Faltan campos requeridos."}

    try:
        conn = sqlite3.connect('chat_manager.db')
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            cursor.execute("UPDATE users SET ip = ?, public_key = ?, last_seen = ? WHERE username = ?",
                           (addr[0], public_key, datetime.now(), username))
            conn.commit()
            conn.close()
            log_message(f"Señal de vida actualizada para {username} desde {addr[0]}.")
            return {"status": "success", "message": "Señal de vida actualizada."}
        else:
            conn.close()
            log_message(f"Error: Usuario no registrado {username} intentando enviar señal de vida.")
            return {"status": "error", "message": "Usuario no registrado."}
    except Exception as e:
        log_message(f"Error en el servidor durante la señal de vida de {username}: {str(e)}")
        return {"status": "error", "message": f"Error en el servidor: {str(e)}"}

#region user
def get_user_info(message):
    requester = message.get("username")
    target = message.get("target_username")

    if not requester or not target:
        return {"status": "error", "message": "Faltan campos requeridos."}

    try:
        conn = sqlite3.connect('chat_manager.db')
        cursor = conn.cursor()
        cursor.execute("SELECT ip, public_key, last_seen FROM users WHERE username = ?", (target,))
        row = cursor.fetchone()
        if row:
            ip, public_key, last_seen = row
            if datetime.now() - datetime.fromisoformat(last_seen) > timedelta(seconds=TIMEOUT):
                conn.close()
                log_message(f"Error: El usuario {target} está desconectado.")
                return {"status": "error", "message": "El usuario está desconectado."}
            conn.close()
            log_message(f"Información del usuario {target} proporcionada a {requester}.")
            return {"status": "success", "ip": ip, "public_key": public_key}
        else:
            conn.close()
            log_message(f"Error: Usuario {target} no encontrado solicitado por {requester}.")
            return {"status": "error", "message": "Usuario no encontrado."}
    except Exception as e:
        log_message(f"Error en el servidor al obtener información de {target}: {str(e)}")
        return {"status": "error", "message": f"Error en el servidor: {str(e)}"}

#region cleanup
def cleanup_users():
    while True:
        try:
            conn = sqlite3.connect('chat_manager.db')
            cursor = conn.cursor()
            cutoff = datetime.now() - timedelta(seconds=TIMEOUT)
            cursor.execute("DELETE FROM users WHERE last_seen < ?", (cutoff,))
            deleted = cursor.rowcount
            conn.commit()
            conn.close()
            if deleted > 0:
                log_message(f"{deleted} usuarios desconectados eliminados por inactividad.")
            time.sleep(ALIVE_INTERVAL)
        except Exception as e:
            log_message(f"Error en limpieza de usuarios: {str(e)}")
            time.sleep(ALIVE_INTERVAL)

#region start
def start_server():
    init_db()
    cleanup_thread = threading.Thread(target=cleanup_users, daemon=True)
    cleanup_thread.start()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        log_message(f"Servidor iniciado en {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            client_thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            client_thread.start()

if __name__ == "__main__":
    start_server()
