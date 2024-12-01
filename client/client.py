import socket
import threading
import json
import time
import os
from getpass import getpass
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import logging
from termcolor import colored as col
import sqlite3
import sys

SERVER_UP = True
BROADCAST_PORT = 55555
BUFFER_SIZE = 1024
DB_FILE = "client_data.db"
CLIENT_PORT = 12345
USER_DATA_PATH = "/app/user_data"


GESTOR_HOST = "192.168.1.2"
GESTOR_PORT = 65432
ALIVE_INTERVAL = 1

PRIVATE_KEY_FILE = "private_key.pem"
PUBLIC_KEY_FILE = "public_key.pem"

stop_event = threading.Event()

logging.basicConfig(
    filename="client.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)


def find_gestor():
    return "192.168.1.2"
    """Descubre la dirección IP del gestor mediante broadcast."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.settimeout(5)

        broadcast_message = b"DISCOVER_GESTOR"
        gestor_ip = None

        try:
            logging.info("Enviando broadcast para descubrir gestor...")
            s.sendto(broadcast_message, ("<broadcast>", BROADCAST_PORT))

            # Esperar respuesta
            data, addr = s.recvfrom(BUFFER_SIZE)
            gestor_ip = data.decode()
            logging.info(f"Gestor descubierto en {gestor_ip} (desde {addr})")
        except socket.timeout:
            logging.warning("No se recibió respuesta del gestor.")
        except Exception as e:
            logging.error(f"Error al buscar el gestor: {e}")
        return gestor_ip


def is_server_active(host, port):
    """
    Verifica si el servidor está activo en la dirección y puerto especificados.

    Args:
        host (str): Dirección IP del servidor.
        port (int): Puerto del servidor.

    Returns:
        bool: True si el servidor está activo, False de lo contrario.
    """
    try:
        with socket.create_connection((host, port), timeout=5):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


# region lock
LOCK_FILE = "client.lock"


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


# region keys
def load_or_generate_keys():
    """
    Carga las llaves RSA existentes desde archivos o genera nuevas si no existen.
    """
    if os.path.exists(PRIVATE_KEY_FILE) and os.path.exists(PUBLIC_KEY_FILE):
        with open(PRIVATE_KEY_FILE, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(), password=None, backend=default_backend()
            )
        with open(PUBLIC_KEY_FILE, "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(), backend=default_backend()
            )
        print("Llaves RSA cargadas exitosamente.")
    else:
        print("Generando nuevas llaves RSA...")
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        public_key = private_key.public_key()

        # Guardar las llaves en archivos
        with open(PRIVATE_KEY_FILE, "wb") as key_file:
            key_file.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        with open(PUBLIC_KEY_FILE, "wb") as key_file:
            key_file.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
        print("Llaves RSA generadas y almacenadas exitosamente.")
    return private_key, public_key


# region register
def register(username, password, public_key_str):
    """
    Registra un nuevo usuario con el nombre de usuario, contraseña y clave pública dados.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((GESTOR_HOST, GESTOR_PORT))
            message = {
                "action": "register",
                "username": username,
                "password": password,
                "public_key": public_key_str,
            }
            s.sendall(json.dumps(message).encode())
            response = s.recv(4096)
            response = json.loads(response.decode())
            return response
    except Exception as e:
        return {"status": "error", "message": f"Error de conexión: {str(e)}"}


# region login
def login(username, password):
    """
    Intenta iniciar sesión de un usuario enviando sus credenciales al servidor.
    """
    global DB_FILE
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((GESTOR_HOST, GESTOR_PORT))
            message = {"action": "login", "username": username, "password": password}
            s.sendall(json.dumps(message).encode())
            response = s.recv(4096)
            response = json.loads(response.decode())

            if response.get("status") == "success":
                DB_FILE = get_user_db(username)
                initialize_user_database(username)

            return response
    except Exception as e:
        return {"status": "error", "message": f"Error de conexión: {str(e)}"}


# region logout
def logout():
    global DB_FILE
    stop_all_threads()
    DB_FILE = "client_data.db"
    print(col("Sesión cerrada correctamente.", "green"))


def stop_all_threads():
    """Detiene todos los hilos en ejecución."""
    stop_event.set()
    print(col("Hilos detenidos.", "yellow"))


# region alive
def send_alive_signal(username, public_key_str, stop_event):
    """
    Envía una señal de vida al servidor a intervalos regulares para indicar que el cliente sigue activo.

    La función intenta conectarse al servidor especificado por GESTOR_HOST y GESTOR_PORT, y envía un mensaje JSON
    con la acción "alive_signal", el nombre de usuario y la clave pública. Si la respuesta del servidor indica éxito,
    se establece SERVER_UP a True. En caso de error, se intenta encontrar un nuevo gestor y actualizar GESTOR_HOST.

    La función se ejecuta en un bucle hasta que se establece el evento stop_event o se alcanza el tiempo de espera
    especificado por ALIVE_INTERVAL.
    """
    global GESTOR_HOST
    global SERVER_UP

    while not stop_event.is_set():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((GESTOR_HOST, GESTOR_PORT))
                message = {
                    "action": "alive_signal",
                    "username": username,
                    "public_key": public_key_str,
                }
                s.sendall(json.dumps(message).encode())
                response = s.recv(4096)
                response = json.loads(response.decode())

                if response.get("status") == "success":
                    SERVER_UP = True
                    logging.info("Señal de vida enviada exitosamente.")
                else:
                    SERVER_UP = False
                    logging.error(f"Error en señal de vida: {response.get('message')}")

        except Exception as e:
            SERVER_UP = False
            logging.error(f"Error al enviar señal de vida: {str(e)}")

            gestor_ip = find_gestor()
            if gestor_ip:
                GESTOR_HOST = gestor_ip
                SERVER_UP = True
                logging.info(f"Nuevo gestor encontrado: {GESTOR_HOST}")
            else:
                logging.error("Gestor no encontrado. SERVER_UP establecido a False.")

        if stop_event.wait(timeout=ALIVE_INTERVAL):
            break


# region user_query
def query_user_info(username, target_username):
    """
    Consulta información de un usuario en el servidor.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((GESTOR_HOST, GESTOR_PORT))
            message = {
                "action": "get_user",
                "username": username,
                "target_username": target_username,
            }
            s.sendall(json.dumps(message).encode())
            response = s.recv(4096)
            response = json.loads(response.decode())
            return response
    except Exception as e:
        return {"status": "error", "message": f"Error de conexión: {str(e)}"}


# region database


def get_user_db(username):
    """Devuelve la ruta de la base de datos específica para un usuario."""
    if not os.path.exists(USER_DATA_PATH):
        os.makedirs(USER_DATA_PATH)
    return os.path.join(USER_DATA_PATH, f"{username}_data.db")


def initialize_user_database(username):
    """Inicializa la base de datos SQLite para un usuario específico."""
    db_file = get_user_db(username)
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()

    # Tabla para almacenar mensajes
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            chat_id INTEGER NOT NULL,
            sender TEXT NOT NULL,
            message TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            delivered INTEGER DEFAULT 0,
            FOREIGN KEY(chat_id) REFERENCES chats(id) ON DELETE CASCADE
        );
    """
    )

    # Tabla para almacenar chats
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS chats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            last_message TEXT,
            last_timestamp DATETIME,
            UNIQUE(username)
        );
    """
    )

    # Tabla para almacenar mensajes pendientes
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS pending_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            receiver TEXT NOT NULL,
            message TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );"""
    )

    conn.commit()
    conn.close()
    print(f"Base de datos inicializada para el usuario '{username}'.")


# region chat


def save_message(chat_id, sender, message, delivered=False):
    """Guarda un mensaje en la base de datos."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO messages (chat_id, sender, message, delivered, timestamp)
        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
    """,
        (chat_id, sender, message, 1 if delivered else 0),
    )

    cursor.execute(
        """
        UPDATE chats
        SET last_message = ?, last_timestamp = CURRENT_TIMESTAMP
        WHERE id = ?
    """,
        (message, chat_id),
    )

    conn.commit()
    conn.close()


def get_chat_messages(chat_id):
    """Obtiene los mensajes de un chat."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT sender, message, timestamp
        FROM messages
        WHERE chat_id = ?
        ORDER BY timestamp ASC
    """,
        (chat_id,),
    )
    messages = cursor.fetchall()
    conn.close()
    return messages


def list_chats():
    """Lista todos los chats activos."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id, username, last_message, last_timestamp
        FROM chats
        ORDER BY last_timestamp DESC
    """
    )
    chats = cursor.fetchall()
    conn.close()
    return chats


def show_chats():
    """Muestra una lista de los chats activos."""
    chats = list_chats()
    if not chats:
        print(col("No tienes chats activos.", "yellow"))
        return

    print(col("Chats activos:", "blue"))
    for chat in chats:
        chat_id, username, last_message, last_timestamp = chat
        print(
            f"{chat_id}: {username} - Último mensaje: '{last_message}' a las {last_timestamp}"
        )


def get_or_create_chat(username):
    """Obtiene o crea un chat con un usuario."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT id FROM chats WHERE username = ?
    """,
        (username,),
    )
    chat = cursor.fetchone()

    if chat is None:
        cursor.execute(
            """
            INSERT INTO chats (username, last_message, last_timestamp)
            VALUES (?, ?, ?)
        """,
            (username, None, None),
        )
        conn.commit()
        chat_id = cursor.lastrowid
    else:
        chat_id = chat[0]

    conn.close()
    return chat_id


def open_chat():
    """Permite al usuario abrir un chat y ver los mensajes."""
    chat_id = input("ID del chat a abrir: ")
    try:
        chat_id = int(chat_id)
        messages = get_chat_messages(chat_id)
        if not messages:
            print(col("No hay mensajes en este chat.", "yellow"))
            return

        print(col("Mensajes:", "blue"))
        for sender, message, timestamp in messages:
            print(f"[{timestamp}] {col(sender, 'cyan')}: {message}")
    except ValueError:
        print(col("ID del chat no válido.", "red"))


def send_message(username):
    """Envía un mensaje a otro usuario."""
    target_username = input("Usuario destino: ")
    message_content = input("Mensaje: ")

    chat_id = get_or_create_chat(target_username)

    response = query_user_info(username, target_username)
    if response.get("status") == "success":
        target_ip = response.get("ip")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                client_socket.connect((target_ip, CLIENT_PORT))
                message = {
                    "sender": username,
                    "content": message_content,
                }
                client_socket.sendall(json.dumps(message).encode())
                print(col("Mensaje enviado con éxito.", "green"))

                save_message(chat_id, username, message_content, delivered=True)
        except Exception as e:
            print(
                col(
                    f"Error al enviar el mensaje. Guardando como pendiente: {str(e)}",
                    "yellow",
                )
            )
            store_pending_message(username, target_username, message_content)
    else:
        print(
            col(
                f"El usuario {target_username} está desconectado o no está registrado.",
                "yellow",
            )
        )
        store_pending_message(username, target_username, message_content)


listener_thread = None


def start_message_listener(username):
    """Inicia un servidor para recibir mensajes de otros usuarios."""
    global listener_thread

    def listen():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.setsockopt(
                socket.SOL_SOCKET, socket.SO_REUSEADDR, 1
            )  # Reutilización del puerto
            server_socket.bind(("", CLIENT_PORT))
            server_socket.listen(5)
            print(
                col(
                    f"[{username}] Escuchando mensajes en el puerto {CLIENT_PORT}...",
                    "green",
                )
            )

            while not stop_event.is_set():
                conn, addr = server_socket.accept()
                with conn:
                    try:
                        message_data = conn.recv(BUFFER_SIZE).decode()
                        message_json = json.loads(message_data)

                        sender = message_json.get("sender")
                        content = message_json.get("content")

                        if not sender or not content:
                            # print(col(f"Mensaje inválido recibido de {addr[0]}", "red"))
                            continue

                        print(col(f"Nuevo mensaje de {sender}: {content}", "cyan"))

                        chat_id = get_or_create_chat(sender)

                        save_message(chat_id, sender, content, delivered=True)
                    except json.JSONDecodeError:
                        print(
                            col(f"Error al decodificar el mensaje de {addr[0]}", "red")
                        )
                    except Exception as e:
                        print(
                            col(
                                f"Error al procesar mensaje de {addr[0]}: {str(e)}",
                                "red",
                            )
                        )

    if listener_thread and listener_thread.is_alive():
        print(col("Listener ya está corriendo.", "yellow"))
        return

    listener_thread = threading.Thread(target=listen, daemon=True)
    listener_thread.start()


# region pending messages


def store_pending_message(sender, receiver, content):
    """Guarda un mensaje pendiente en la base de datos."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO pending_messages (sender, receiver, message, timestamp)
        VALUES (?, ?, ?, datetime('now'))
    """,
        (sender, receiver, content),
    )
    conn.commit()
    conn.close()
    print(col(f"Mensaje pendiente almacenado para {receiver}.", "yellow"))


def start_pending_message_worker(username):
    """Inicia un hilo en segundo plano para intentar entregar mensajes pendientes."""

    def worker():
        while not stop_event.is_set():
            check_and_send_pending_messages(username)
            time.sleep(5)  # Intervalo de 5 segundos entre verificaciones

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()


def check_and_send_pending_messages(username):
    """Revisa y envía mensajes pendientes."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Obtener mensajes pendientes
    cursor.execute(
        """
        SELECT id, receiver, message FROM pending_messages
    """
    )
    pending_messages = cursor.fetchall()

    for msg_id, receiver, message_content in pending_messages:
        target_ip = get_cached_ip(receiver)

        # Intentar enviar el mensaje con el servidor activo
        if SERVER_UP:
            response = query_user_info(username, receiver)
            if response.get("status") == "success":
                target_ip = response.get("ip")
                update_cached_ip(receiver, target_ip)  # Actualizar la IP cacheada
                if send_message_to_ip(target_ip, username, receiver, message_content):
                    cursor.execute(
                        "DELETE FROM pending_messages WHERE id = ?", (msg_id,)
                    )
                    conn.commit()
                    save_message_to_chat(receiver, username, message_content)
                continue
            else:
                logging.warning(
                    f"El usuario {receiver} no está conectado. {response.get('message')}"
                )

        # Si el servidor no está activo, usar la IP cacheada
        elif target_ip:
            logging.info(f"Intentando usar la IP cacheada para {receiver}: {target_ip}")
            if send_message_to_ip(target_ip, username, receiver, message_content):
                cursor.execute("DELETE FROM pending_messages WHERE id = ?", (msg_id,))
                conn.commit()
                save_message_to_chat(receiver, username, message_content)
            else:
                logging.warning(
                    f"No se pudo entregar el mensaje a {receiver} en {target_ip}."
                )
        else:
            logging.warning(f"No hay IP cacheada para {receiver}.")

    conn.close()


def send_message_to_ip(ip, sender, receiver, message_content):
    """Intenta conectar y enviar un mensaje al destinatario en una IP específica."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.settimeout(5)  # Timeout para conexiones
            client_socket.connect((ip, CLIENT_PORT))
            message = {
                "sender": sender,
                "content": message_content,
            }
            client_socket.sendall(json.dumps(message).encode())
            print(col(f"Mensaje entregado a {receiver}: {message_content}", "green"))
            return True
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        logging.error(f"Error al intentar conectar con {receiver} en {ip}: {str(e)}")
    return False


def save_message_to_chat(receiver, sender, message_content):
    """Guarda un mensaje entregado en la tabla de mensajes y actualiza el chat."""
    chat_id = get_or_create_chat(receiver)
    save_message(chat_id, sender, message_content, delivered=True)


cache = {}


def get_cached_ip(username):
    """Obtiene la IP cacheada de un usuario."""
    return cache.get(username)


def update_cached_ip(username, ip):
    """Actualiza la IP cacheada de un usuario."""
    cache[username] = ip
    print(col(f"IP cacheada para {username} actualizada a {ip}.", "blue"))


# region main
def main():
    global GESTOR_HOST, stop_event

    GESTOR_HOST = find_gestor()

    if is_server_active(GESTOR_HOST, GESTOR_PORT):
        print(col("El servidor está activo.", "green"))
    else:
        SERVER_UP = False
        print(col("El servidor no está activo.", "red"))

    private_key, public_key = load_or_generate_keys()
    public_key_str = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    print(col("Bienvenido al Cliente de Chat P2P", "blue"))
    while True:
        print("\nSelecciona una opción:")
        print("\t1. Registrarse")
        print("\t2. Iniciar Sesión")
        print("\t3. Salir")
        choice = input("Opción: ")

        if choice == "1":
            username = input(col("\tNombre de usuario: ", "blue"))
            password = getpass(col("\tContraseña: ", "blue"))
            confirm_password = getpass(col("\tConfirmar Contraseña: ", "blue"))
            if password != confirm_password:
                print(col("Las contraseñas no coinciden. Intenta nuevamente.", "red"))
                continue
            response = register(username, password, public_key_str)
            print(response.get("message"))
            if response.get("status") == "success":
                print(col("Puedes ahora iniciar sesión.", "green"))
            print("")
        elif choice == "2":
            username = input(col("\tNombre de usuario: ", "blue"))
            password = getpass(col("\tContraseña: ", "blue"))
            response = login(username, password)
            print(response.get("message"))
            if response.get("status") == "success":
                stop_event.clear()
                start_message_listener(username)
                start_pending_message_worker(username)

                alive_thread = threading.Thread(
                    target=send_alive_signal,
                    args=(username, public_key_str, stop_event),
                    daemon=True,
                )
                alive_thread.start()

                while True:
                    print("\nOpciones disponibles:")
                    print("\t1. Consultar usuario")
                    print("\t2. Enviar mensaje")
                    print("\t3. Ver chats")
                    print("\t4. Abrir un chat")
                    print("\t5. Cerrar sesión")
                    sub_choice = input("Opción: ")

                    if sub_choice == "1":
                        target_username = input("\tNombre de usuario a consultar: ")
                        response = query_user_info(username, target_username)
                        if response.get("status") == "success":
                            print(col(f"{response.get('ip')}", "magenta"))
                            # print(f"Llave Pública:\n{response.get('public_key')}")
                        else:
                            print(col(f"Error: {response.get('message')}", "red"))
                    elif sub_choice == "2":
                        send_message(username)
                    elif sub_choice == "3":
                        show_chats()
                    elif sub_choice == "4":
                        open_chat()
                    elif sub_choice == "5":
                        print("Cerrando sesión...")
                        stop_event.set()
                        alive_thread.join()
                        break
                    else:
                        print(col("Opción no válida. Intenta nuevamente.", "red"))
                print("")

        elif choice == "3":
            print("Saliendo del cliente. ¡Hasta luego!")
            print("")
            break
        else:
            print(col("Opción no válida. Intenta nuevamente.", "red"))
            print("")


if __name__ == "__main__":
    check_single_instance()
    try:
        main()
    finally:
        remove_lock()
