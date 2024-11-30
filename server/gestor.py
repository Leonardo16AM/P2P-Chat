import socket
import threading
import sqlite3
import json
import bcrypt
import time
from datetime import datetime, timedelta
import sys
import os
import subprocess

# region config
HOST = "0.0.0.0"  # Escuchar en todas las interfaces
PORT = 65432  # Puerto a usar
ALIVE_INTERVAL = 10  # Intervalo de alive_signal en segundos
TIMEOUT = 60  # Tiempo antes de considerar a un usuario como desconectado
LOG_FILE = "gestor.log"

# region lock
LOCK_FILE = "gestor.lock"


def check_single_instance():
    if os.path.exists(LOCK_FILE):
        print("Otra instancia del cliente ya está en ejecución.")
        sys.exit()
    else:
        with open(LOCK_FILE, "w") as f:
            f.write("lock")


def remove_lock():
    if os.path.exists(LOCK_FILE):
        os.remove(LOCK_FILE)


# region DDNS
DDNS_ZONE_FILE = "./db.server"
SERVER_NAME = "server"
PREVIOUS_IP = None


def get_container_ip(container_name, network_name):
    """
    Obtiene la dirección IP de un contenedor en una red específica ejecutando `docker inspect`.
    """
    try:
        result = subprocess.run(
            [
                "docker",
                "inspect",
                "-f",
                f"{{{{.NetworkSettings.Networks.{network_name}.IPAddress}}}}",
                container_name,
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        ip_address = result.stdout.strip()
        if ip_address:
            return ip_address
        else:
            log_message(
                f"No se encontró una IP para el contenedor {container_name} en la red {network_name}."
            )
            return None
    except subprocess.CalledProcessError as e:
        log_message(f"Error al ejecutar docker inspect: {e}")
        return None


def update_ddns(new_ip):
    """
    Actualiza el archivo de zona de DDNS y recarga CoreDNS.
    """
    global PREVIOUS_IP

    if new_ip == PREVIOUS_IP:
        return

    try:
        with open(DDNS_ZONE_FILE, "r") as f:
            lines = f.readlines()

        updated_lines = []
        for line in lines:
            if line.startswith(f"{SERVER_NAME}\tIN\tA"):
                updated_lines.append(f"{SERVER_NAME}\tIN\tA\t{new_ip}\n")
            else:
                updated_lines.append(line)

        with open(DDNS_ZONE_FILE, "w") as f:
            f.writelines(updated_lines)

        subprocess.run(["docker", "exec", "ddns", "kill", "-HUP", "1"], check=True)
        PREVIOUS_IP = new_ip
        log_message(f"DDNS actualizado: {SERVER_NAME} -> {new_ip}")

    except Exception as e:
        log_message(f"Error al actualizar el DDNS: {e}")


def monitor_and_update(container_name, network_name):
    """
    Monitorea continuamente la IP del contenedor y actualiza el DDNS si es necesario.
    """
    while True:
        try:
            current_ip = get_container_ip(container_name, network_name)
            if current_ip:
                update_ddns(current_ip)
            else:
                print("No se pudo obtener la IP actual.")
        except Exception as e:
            print(f"Error durante la actualización de DDNS: {e}")

        time.sleep(7)


# region db_init
def init_db():
    conn = sqlite3.connect("chat_manager.db")
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password BLOB NOT NULL,
            ip TEXT NOT NULL,
            public_key TEXT NOT NULL,
            last_seen TIMESTAMP NOT NULL,
            status TEXT NOT NULL DEFAULT 'disconnected'
        )
    """
    )
    conn.commit()
    conn.close()


# region logs
def log_message(message):
    with open(LOG_FILE, "a") as log_file:
        log_file.write(f"{datetime.now()} - {message}\n")


# region utils
def handle_client(conn, addr):
    log_message(f">> Conexión establecida desde {addr}")
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            try:
                log_message(f"\tDatos recibidos desde {addr}: {data.decode()}")
                message = json.loads(data.decode())
                response = process_message(message, addr)
            except json.JSONDecodeError:
                response = {"status": "error", "message": "Formato JSON inválido."}
                log_message(f"\tError de JSON desde {addr}: {data}")
            conn.sendall(json.dumps(response).encode())
            log_message(f"\tRespuesta enviada a {addr}: {response}")
    except ConnectionResetError:
        log_message(f"\tConexión perdida con {addr}")
    finally:
        conn.close()


def process_message(message, addr):
    log_message(f"\tProcesando mensaje desde {addr}: {message}")
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
        log_message(f"\tAcción no reconocida desde {addr}: {action}")
        return {"status": "error", "message": "Acción no reconocida."}


# region register
def register_user(message):
    username = message.get("username")
    password = message.get("password")
    public_key = message.get("public_key")

    log_message(f"\tIntento de registro: {message}")

    if not username or not password or not public_key:
        log_message("Error: Campos faltantes durante el registro.")
        return {"status": "error", "message": "Faltan campos requeridos."}

    try:
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        conn = sqlite3.connect("chat_manager.db")
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, password, ip, public_key, last_seen, status) VALUES (?, ?, ?, ?, ?, ?)",
            (username, hashed, "", public_key, datetime.now(), "disconnected"),
        )
        conn.commit()
        conn.close()
        log_message(f"\tUsuario {username} registrado exitosamente.")
        return {"status": "success", "message": "Usuario registrado exitosamente."}
    except sqlite3.IntegrityError:
        log_message(f"\tError: El nombre de usuario {username} ya existe.")
        return {"status": "error", "message": "El nombre de usuario ya existe."}
    except Exception as e:
        log_message(
            f"\tError en el servidor durante el registro de {username}: {str(e)}"
        )
        return {"status": "error", "message": f"Error en el servidor: {str(e)}"}


# region login
def login_user(message, addr):
    username = message.get("username")
    password = message.get("password")

    log_message(f"\tIntento de login: {message} desde {addr}")

    if not username or not password:
        log_message("Error: Campos faltantes durante el inicio de sesión.")
        return {"status": "error", "message": "Faltan campos requeridos."}

    try:
        conn = sqlite3.connect("chat_manager.db")
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        if row and bcrypt.checkpw(password.encode(), row[0]):
            cursor.execute(
                "UPDATE users SET ip = ?, last_seen = ?, status = ? WHERE username = ?",
                (addr[0], datetime.now(), "connected", username),
            )
            conn.commit()
            conn.close()
            log_message(
                f"\tUsuario {username} autenticado exitosamente desde {addr[0]}."
            )
            return {"status": "success", "message": "Autenticación exitosa."}
        else:
            conn.close()
            log_message(f"\tError: Credenciales inválidas para {username}.")
            return {"status": "error", "message": "Credenciales inválidas."}
    except Exception as e:
        log_message(
            f"\tError en el servidor durante el inicio de sesión de {username}: {str(e)}"
        )
        return {"status": "error", "message": f"Error en el servidor: {str(e)}"}


# region alive
def alive_signal(message, addr):
    username = message.get("username")
    public_key = message.get("public_key")

    log_message(f"\t\tSeñal de vida recibida: {message} desde {addr}")

    if not username or not public_key:
        log_message("Error: Campos faltantes en señal de vida.")
        return {"status": "error", "message": "Faltan campos requeridos."}

    try:
        conn = sqlite3.connect("chat_manager.db")
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            cursor.execute(
                "UPDATE users SET ip = ?, public_key = ?, last_seen = ?, status = ? WHERE username = ?",
                (addr[0], public_key, datetime.now(), "connected", username),
            )
            conn.commit()
            conn.close()
            log_message(
                f"\t\tSeñal de vida actualizada para {username} desde {addr[0]}."
            )
            return {"status": "success", "message": "Señal de vida actualizada."}
        else:
            conn.close()
            log_message(
                f"\tError: Usuario no registrado {username} intentando enviar señal de vida."
            )
            return {"status": "error", "message": "Usuario no registrado."}
    except Exception as e:
        log_message(
            f"\tError en el servidor durante la señal de vida de {username}: {str(e)}"
        )
        return {"status": "error", "message": f"Error en el servidor: {str(e)}"}


# region user_info
def get_user_info(message):
    requester = message.get("username")
    target = message.get("target_username")

    log_message(f"\tSolicitud de información del usuario {target} por {requester}")

    if not requester or not target:
        log_message("Error: Campos faltantes en solicitud de información del usuario.")
        return {"status": "error", "message": "Faltan campos requeridos."}

    try:
        conn = sqlite3.connect("chat_manager.db")
        cursor = conn.cursor()
        cursor.execute(
            "SELECT ip, public_key, last_seen, status FROM users WHERE username = ?",
            (target,),
        )
        row = cursor.fetchone()
        if row:
            ip, public_key, last_seen, status = row
            if status != "connected":
                conn.close()
                log_message(f"\tError: El usuario {target} está desconectado.")
                return {"status": "error", "message": "El usuario está desconectado."}
            conn.close()
            log_message(
                f"\tInformación del usuario {target} proporcionada a {requester}."
            )
            return {"status": "success", "ip": ip, "public_key": public_key}
        else:
            conn.close()
            log_message(
                f"\tError: Usuario {target} no encontrado solicitado por {requester}."
            )
            return {"status": "error", "message": "Usuario no encontrado."}
    except Exception as e:
        log_message(
            f"\tError en el servidor al obtener información de {target}: {str(e)}"
        )
        return {"status": "error", "message": f"Error en el servidor: {str(e)}"}


# region disconect
def cleanup_users():
    while True:
        try:
            conn = sqlite3.connect("chat_manager.db")
            cursor = conn.cursor()
            cutoff = datetime.now() - timedelta(seconds=TIMEOUT)
            cursor.execute(
                "UPDATE users SET status = 'disconnected' WHERE last_seen < ?",
                (cutoff,),
            )
            updated = cursor.rowcount
            conn.commit()
            conn.close()
            if updated > 0:
                log_message(
                    f"\t{updated} usuarios actualizados a estado 'disconnected' por inactividad."
                )
            time.sleep(ALIVE_INTERVAL)
        except Exception as e:
            log_message(f"\tError en limpieza de usuarios: {str(e)}")
            time.sleep(ALIVE_INTERVAL)


# region startup
def start_server():
    CONTAINER_NAME = "server"
    NETWORK_NAME = "server_network"

    monitor_thread = threading.Thread(
        target=monitor_and_update, args=(CONTAINER_NAME, NETWORK_NAME), daemon=True
    )
    monitor_thread.start()

    init_db()
    cleanup_thread = threading.Thread(target=cleanup_users, daemon=True)
    cleanup_thread.start()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        log_message(f"\tServidor iniciado en {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            client_thread = threading.Thread(
                target=handle_client, args=(conn, addr), daemon=True
            )
            client_thread.start()


if __name__ == "__main__":
    check_single_instance()
    try:
        start_server()
    finally:
        remove_lock()
