# gestor/client_handler.py
import json
import socket
import random
import bcrypt
import sqlite3
from datetime import datetime
from .config import DB_FILE, HOST, CLIENT_PORT, ALIVE_INTERVAL, TIMEOUT, VERBOSE
from .logging import log_message
from .db import db_lock
from .ring import find_successor, hash as chord_hash, rint, replicate, print_db
from termcolor import colored as col
from datetime import datetime, timedelta
import time

import server.global_state as gs


# region get_user_data
def get_user_data(username: str, table: str) -> dict:
    """
    Retrieves user data from the specified SQLite database table based on a given username.

    Args:
        username (str): The username to search for in the specified table.
        table (str): The name of the SQLite database table to query.

    Returns:
        dict or None: A dictionary containing the user data if found, otherwise None.

    Raises:
        sqlite3.Error: If an error occurs during the SQL query execution.
    """
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    query = f"SELECT * FROM {table} WHERE username = ?"

    try:
        cursor.execute(query, (username,))
        row = cursor.fetchone()
    except sqlite3.Error as e:
        print(f"Error en la consulta SQL: {e}")
        row = None
    finally:
        conn.close()

    return dict(row) if row else None


# region cleanup_users
def cleanup_users() -> None:
    """
    Periodically updates the status of inactive users in the database to 'disconnected'.
    """
    while True:
        try:
            conn = sqlite3.connect(DB_FILE)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cutoff = datetime.now() - timedelta(seconds=5)
            cursor.execute(
                "SELECT * FROM users WHERE last_update < ? AND status = 'connected'",
                (cutoff,),
            )
            users_to_update = cursor.fetchall()

            if users_to_update:
                cursor.execute(
                    "UPDATE users SET status = 'disconnected' WHERE last_update < ? AND status = 'connected'",
                    (cutoff,),
                )
                updated = cursor.rowcount
                conn.commit()

                users_dict_list = [dict(user) for user in users_to_update]
                for user in users_dict_list:
                    user['status']='disconnected'
                log_message(
                    f"\t{updated} usuarios actualizados a estado 'disconnected' por inactividad."
                )
                replicate(users_dict_list)
                VERBOSE and print_db()
            conn.close()
            time.sleep(ALIVE_INTERVAL)
        except Exception as e:
            log_message(f"\tError en limpieza de usuarios: {str(e)}")
            time.sleep(ALIVE_INTERVAL)


# region process_register
def process_register(message: dict) -> dict:
    """
    Registers a new user in the system.

    This function inserts a new user record into the database with the provided
    username, password, and public key. Passwords are hashed before storage. If
    the user already exists, it returns an appropriate error message.

    Args:
        message (dict): A dictionary containing the following keys:
            - username (str): The username of the new user.
            - password (str): The plaintext password to be hashed and stored.
            - public_key (str): The public key associated with the user.

    Returns:
        dict: A dictionary with a status key ('success' or 'error') and a
        corresponding message. If successful, the function also replicates
        new user data across the system.
    """
    username = message.get("username")
    password = message.get("password")
    public_key = message.get("public_key")
    if not username or not password or not public_key:
        return {"status": "error", "message": "Faltan campos requeridos."}
    try:
        with db_lock:
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode("utf-8")

            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute(
                """
                INSERT INTO users (username, password, ip, public_key, last_update, status)
                VALUES (?, ?, ?, ?, ?, ?)
            """,
                (username, hashed, "", public_key, now_str, "disconnected"),
            )
            conn.commit()
            conn.close()
        log_message(f"Usuario '{username}' registrado.")
        replicate([get_user_data(username, "users")])
        VERBOSE and print_db()
        return {"status": "success", "message": "Usuario registrado exitosamente."}
    except sqlite3.IntegrityError:
        log_message(f"Registro fallido: usuario '{username}' ya existe.")
        return {"status": "error", "message": "El nombre de usuario ya existe."}
    except Exception as e:
        log_message(f"Error en register: {e}")
        return {"status": "error", "message": str(e)}


# region process_login
def process_login(message: str, addr: tuple) -> dict:
    """
    Processes user login.
    Verifies credentials and updates the user's IP in the database.
    """
    username = message.get("username")
    password = message.get("password")
    if not username or not password:
        return {"status": "error", "message": "Faltan campos requeridos."}
    try:
        with db_lock:
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT password, ip FROM users WHERE username = ?", (username,)
            )
            row = cursor.fetchone()
            if row is None:
                conn.close()
                log_message(f"Login fallido: usuario '{username}' no existe.")
                return {"status": "error", "message": "Usuario no encontrado."}
            stored_password, current_ip = row

            if not bcrypt.checkpw(password.encode(), stored_password.encode("utf-8")):
                conn.close()
                log_message(f"Login fallido: contraseña incorrecta para '{username}'.")
                return {"status": "error", "message": "Contraseña incorrecta."}
            # Actualizamos IP del usuario si es necesario (suponiendo que addr[0] es la IP)
            new_ip = addr[0]
            cursor.execute(
                "UPDATE users SET ip = ?, last_update = datetime('now'), status = ? WHERE username = ?",
                (new_ip, "connected", username),
            )
            conn.commit()
            conn.close()
        replicate([get_user_data(username, "users")])
        log_message(f"Usuario '{username}' inició sesión correctamente desde {new_ip}.")
        VERBOSE and print_db()
        return {"status": "success", "message": "Login exitoso.", "ip": new_ip}
    except Exception as e:
        log_message(f"Error en login: {e}")
        return {"status": "error", "message": str(e)}


# region process_alive_signal
def process_alive_signal(message: str, addr: tuple) -> dict:
    """
    Processes a client's alive signal.
    Updates the user's status to 'connected' and refreshes the 'last_update'.
    If the client's IP (addr[0]) does not match the registered one, it returns
    a response with status "disconnect", the new IP, and a flag for data transfer.
    """
    username = message.get("username")
    if not username:
        return {"status": "error", "message": "Username no proporcionado."}
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT ip FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        if row:
            ip = row[0]
        conn.commit()
        conn.close()
        if addr[0] != ip:
            return {"status": "disconnect", "new_ip": ip, "action": "transfer_data"}

        with db_lock:
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET last_update = datetime('now'), status = ? WHERE username = ?",
                ("connected", username),
            )
            conn.commit()
            conn.close()
        return {"status": "success", "message": "Alive signal procesado."}
    except Exception as e:
        log_message(f"Error en alive_signal: {e}")
        return {"status": "error", "message": str(e)}


# region process_get_user
def process_get_user(message: dict) -> dict:
    """
    Queries and returns information associated with a user.
    """
    username = message.get("target_username")

    if not username:
        return {"status": "error", "message": "Username no proporcionado."}
    try:
        with db_lock:
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT username, ip, public_key, last_update, status FROM users WHERE username = ?",
                (username,),
            )
            row = cursor.fetchone()
            conn.close()

        if row is None:
            log_message(f"Consulta get_user: usuario '{username}' no encontrado.")
            return {"status": "error", "message": "Usuario no encontrado."}

        if row[4] != "connected":
            conn.close()
            log_message(f"\tError: El usuario {username} está desconectado.")
            return {"status": "error", "message": "El usuario está desconectado."}

        user_info = {
            "status": "success",
            "username": row[0],
            "ip": row[1],
            "public_key": row[2],
            "last_update": row[3],
        }
        log_message(f"Información consultada para el usuario '{username}'.")
        return user_info
    except Exception as e:
        log_message(f"Error en get_user: {e}")
        return {"status": "error", "message": str(e)}


# region process_client_message
def process_client_message(message: str, addr: tuple) -> dict:
    """
    Processes a message received from a client and performs the corresponding action.

    Args:
        message (dict): The message received from the client. It should contain an "action" key.
        addr (tuple): The address of the client.

    Returns:
        dict: A dictionary containing the result of the action performed. If the action is not recognized,
              it returns a dictionary with "status" set to "error" and a corresponding error message.
    """
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


# region forward_request_to_node
def forward_request_to_node(target_node: dict, message: dict) -> dict:
    """
    Sends the request to the specified node and returns the response.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            s.connect((target_node["ip"], CLIENT_PORT))
            s.sendall(json.dumps(message).encode())
            response_data = s.recv(4096)
            return json.loads(response_data.decode())
    except Exception as e:
        log_message(f"Error reenviando solicitud a nodo {target_node.get('id')}: {e}")
        return {
            "status": "error",
            "message": "Error comunicándose con el nodo responsable.",
        }


# region handle_client
def handle_client(conn: socket.socket, addr: tuple) -> None:
    """
    Handles the communication with a connected client.

    Args:
        conn (socket.socket): The connection object for the client.
        addr (tuple): The address of the client in the form (ip, port).

    Processes incoming messages from the client, determines the appropriate action based on the message content,
    and sends back a response. If the message contains a username, it calculates the node responsible for the user
    and either processes the message or forwards it to the responsible node. If no username is provided, it sends
    back an error response.

    The function also handles exceptions and ensures the connection is closed after processing.

    Raises:
        Exception: If there is an error during message processing or communication.
    """

    try:
        data = conn.recv(4096)
        if not data:
            return
        message = json.loads(data.decode())

        try:
            if message["action"] != "alive_signal":
                print(col(message, "magenta"))
        except Exception as e:
            pass

        if message.get("ip", -1) == -1:
            message["ip"] = addr[0]
        else:
            addr = [message["ip"], addr[1]]

        username = message.get("username")

        if username:
            if message["action"] == "get_user":
                username = message["target_username"]
            node_hash = chord_hash(username)
            responsible = find_successor(node_hash, event=rint(), hard_mode=False)
            if responsible["id"] == gs.my_node_id:
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
