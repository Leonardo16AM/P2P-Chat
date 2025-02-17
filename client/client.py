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
import struct

SERVER_UP = True
BROADCAST_PORT = 55555
BUFFER_SIZE = 1024
DB_FILE = "client_data.db"
CLIENT_PORT = 12345
USER_DATA_PATH = "/app/user_data"


GESTOR_HOST = "192.168.1.2"
GESTOR_PORT = 65434
ALIVE_INTERVAL = 1

PRIVATE_KEY_FILE = "private_key.pem"
PUBLIC_KEY_FILE = "public_key.pem"

stop_event = threading.Event()
loguedout=False

logging.basicConfig(
    filename="client.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)


def discover_servers(timeout=3):
    """
    Envía una petición multicast para descubrir servidores y espera respuestas.

    :param timeout: Tiempo máximo (en segundos) para esperar respuestas.
    :return: Lista con las IPs de los servidores descubiertos.
    """
    MCAST_GRP = '224.0.0.1'
    MCAST_PORT = 10003
    MESSAGE = "DISCOVER_SERVER"
    BUFFER_SIZE = 1024

    # Crear socket UDP para enviar y recibir
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(timeout)

    # Configurar TTL del paquete multicast
    ttl = struct.pack('b', 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)

    # Enviar la petición multicast
    try:
        sock.sendto(MESSAGE.encode(), (MCAST_GRP, MCAST_PORT))
    except Exception as e:
        print(f"Error enviando el mensaje multicast: {e}")
        return []

    servers = []
    start_time = time.time()
    while True:
        try:
            data, addr = sock.recvfrom(BUFFER_SIZE)
            server_ip = data.decode().strip()
            servers.append(server_ip)
            print(f"Servidor descubierto: {server_ip} (respuesta desde {addr})")
        except socket.timeout:
            break
        except Exception as e:
            print(f"Error recibiendo datos: {e}")
            break
        if time.time() - start_time > timeout:
            break

    sock.close()
    return servers


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
        with socket.create_connection((host, port), timeout=1):
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


def stop_all_threads():
    """Detiene todos los hilos en ejecución."""
    stop_event.set()


# region alive
def send_alive_signal(username, public_key_str, stop_event):
    global GESTOR_HOST
    global SERVER_UP

    while not stop_event.is_set():
        global loguedout
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                s.connect((GESTOR_HOST, GESTOR_PORT))
                message = {
                    "action": "alive_signal",
                    "username": username,
                    "public_key": public_key_str
                }
                s.sendall(json.dumps(message).encode())
                response = s.recv(4096)
                response = json.loads(response.decode())

                if response.get("status") == "success":
                    SERVER_UP = True
                    logging.info("Señal de vida enviada exitosamente.")
                elif response.get("status") == "disconnect":
                    new_ip = response.get("new_ip")
                    print(col("Otro cliente se ha conectado. Transfiriendo datos al nuevo cliente...", "red"))
                    transfer_local_data(new_ip, CLIENT_PORT)
                    print(col('Cerrando sesión...', 'red'))
                    print('Presione enter para continuar...')
                    loguedout=True
                    logout()  # Simula el cierre de sesión en el cliente antiguo
                    return
                else:
                    SERVER_UP = False
                    logging.error(f"Error en señal de vida: {response.get('message')}")
        except socket.timeout:
            logging.warning("Operación de socket agotó el tiempo de espera.")
            SERVER_UP = False
        except Exception as e:
            SERVER_UP = False
            logging.error(f"Error al enviar señal de vida: {str(e)}")
            gestor_ip=False
            try:
                gestor_ip = discover_servers()[0]
            except Exception as e:
                pass
            if gestor_ip:
                GESTOR_HOST = gestor_ip
                SERVER_UP = True
                logging.info(f"Nuevo gestor encontrado: {GESTOR_HOST}")
            else:
                logging.error("Gestor no encontrado. SERVER_UP establecido a False.")

        if stop_event.wait(timeout=ALIVE_INTERVAL):
            break

    logging.info("Hilo send_alive_signal finalizado.")




def transfer_local_data(new_ip, port, retries=3, delay=2):
    """
    Extrae los datos locales (chats, mensajes y mensajes pendientes)
    y los envía al nuevo cliente, que escucha en el puerto 'port'.
    
    En caso de error de conexión (p.ej. Connection Refused), reintenta la conexión
    'retries' veces con un retraso de 'delay' segundos entre intentos.
    """
    try:
        # Extraer datos de la base de datos local
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM chats")
        chats = cursor.fetchall()
        cursor.execute("SELECT * FROM messages")
        messages = cursor.fetchall()
        cursor.execute("SELECT * FROM pending_messages")
        pending = cursor.fetchall()
        conn.close()

        data = {
            "action": "transfer_data",
            "chats": chats,
            "messages": messages,
            "pending": pending
        }
    except Exception as e:
        print(col(f"Error al extraer datos locales: {e}", "red"))
        return

    attempt = 0
    while attempt < retries:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                s.connect((new_ip, port))
                s.sendall(json.dumps(data).encode())
                print(col("Datos transferidos al nuevo cliente.", "green"))
                return  # Salimos si la transferencia es exitosa
        except Exception as e:
            attempt += 1
            print(col(f"Error en transferencia de datos (intento {attempt}): {e}", "red"))
            time.sleep(delay)
    
    print(col("No se pudo transferir los datos tras varios intentos.", "red"))




# region user_query
def query_user_info(username, target_username):
    """Consulta la información de un usuario en el servidor y actualiza la caché."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((GESTOR_HOST, GESTOR_PORT))
            message = {
                "action": "get_user",
                "username": username,
                "target_username": target_username,
            }
            s.sendall(json.dumps(message).encode())
            response = json.loads(s.recv(BUFFER_SIZE).decode())

            if response.get("status") == "success":
                target_ip = response.get("ip")
                update_cached_ip(target_username, target_ip)
            return response
    except Exception as e:
        print(col(f"Error al consultar información del servidor: {str(e)}", "red"))
        return {"status": "error", "message": "No se pudo conectar al servidor."}


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


# region send_message
def send_message(username):
    """Envía un mensaje a otro usuario."""
    target_username = input("Usuario destino: ")
    message_content = input("Mensaje: ")

    chat_id = get_or_create_chat(target_username)

    if is_server_active(GESTOR_HOST, GESTOR_PORT):
        response = query_user_info(username, target_username)
        if response.get("status") == "success":
            target_ip = response.get("ip")
            update_cached_ip(target_username, target_ip)
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                    client_socket.settimeout(2)
                    client_socket.connect((target_ip, CLIENT_PORT))
                    message = {
                        "sender": username,
                        "content": message_content,
                    }
                    client_socket.sendall(json.dumps(message).encode())
                    print(col(f"Mensaje entregado a {target_username}: {message_content}", "green"))

                    save_message(chat_id, username, message_content, delivered=True)
            except Exception as e:
                print(
                    col(
                        f"Error al enviar el mensaje. Guardando como pendiente: {str(e)}",
                        "yellow",
                    )
                )
                store_pending_message(username, target_username, message_content)
            return
    else:
        print(
            col(
                f"No se encontro al gestor en la red.",
                "yellow",
            )
        )
        cached_ip = get_cached_ip(target_username)
        if cached_ip:
            print(
                col(
                    f"Intentando con la IP cacheada para {target_username}: {cached_ip}",
                    "blue",
                )
            )
            success = send_message_to_ip(
                cached_ip, username, target_username, message_content
            )
            if success:
                save_message(chat_id, username, message_content, delivered=True)
                return

    print(
        col(
            f"El usuario {target_username} está desconectado o no está registrado.",
            "yellow",
        )
    )
    store_pending_message(username, target_username, message_content)


# region start_message_listener
listener_thread = None


def start_message_listener(username):
    """Inicia un servidor para recibir mensajes de otros usuarios."""
    global listener_thread

    def listen():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(("", CLIENT_PORT))
            server_socket.listen(5)
            server_socket.settimeout(1)
            print(
                col(
                    f"[{username}] Escuchando mensajes en el puerto {CLIENT_PORT}...",
                    "green",
                )
            )

            while not stop_event.is_set():
                try:
                    conn, addr = server_socket.accept()
                    with conn:
                        message_data = conn.recv(BUFFER_SIZE).decode()
                        message_json = json.loads(message_data)

                        if message_json.get("action") == "who_is_connected":
                            conn.sendall(json.dumps({"username": username}).encode())
                            continue
                        elif message_json.get("action") == "transfer_data":
                            merge_local_data(message_json)
                            continue

                        sender = message_json.get("sender")
                        content = message_json.get("content")
                        if not sender or not content:
                            continue

                        print(col(f"Nuevo mensaje de {sender}: {content}", "cyan"))
                        update_cached_ip(sender, addr[0])
                        chat_id = get_or_create_chat(sender)
                        save_message(chat_id, sender, content, delivered=True)
                except socket.timeout:
                    continue
                except Exception as e:
                    print(col(f"Error al procesar mensaje: {str(e)}", "red"))

            logging.info("Hilo message_listener finalizado.")

    if listener_thread and listener_thread.is_alive():
        logging.info(col("Listener ya está corriendo.", "yellow"))
        return

    listener_thread = threading.Thread(target=listen, daemon=True)
    listener_thread.start()


def merge_local_data(data):
    """
    Fusiona los datos transferidos (chats, mensajes y mensajes pendientes)
    en la base de datos local del nuevo cliente.
    """
    try:
        chats = data.get("chats", [])
        messages = data.get("messages", [])
        pending = data.get("pending", [])
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        # Insertar o actualizar chats
        for chat in chats:
            # Se asume que chat es una tupla: (id, username, last_message, last_timestamp)
            username = chat[1]
            cursor.execute("SELECT id FROM chats WHERE username = ?", (username,))
            if cursor.fetchone() is None:
                cursor.execute("INSERT INTO chats (username, last_message, last_timestamp) VALUES (?, ?, ?)",
                               (chat[1], chat[2], chat[3]))
        # Insertar mensajes
        for msg in messages:
            # Se asume que msg es una tupla: (id, chat_id, sender, message, timestamp, delivered)
            cursor.execute("INSERT INTO messages (chat_id, sender, message, timestamp, delivered) VALUES (?, ?, ?, ?, ?)",
                           (msg[1], msg[2], msg[3], msg[4], msg[5]))
        # Insertar mensajes pendientes
        for p in pending:
            # Se asume que p es una tupla: (id, sender, receiver, message, timestamp)
            cursor.execute("INSERT INTO pending_messages (sender, receiver, message, timestamp) VALUES (?, ?, ?, ?)",
                           (p[1], p[2], p[3], p[4]))
        conn.commit()
        conn.close()
        print(col("Datos transferidos y fusionados en el nuevo cliente.", "green"))
    except Exception as e:
        print(col(f"Error al fusionar datos: {e}", "red"))



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
            if stop_event.wait(timeout=5):
                break

        logging.info("Hilo pending_message_worker terminado")

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

        if is_server_active(GESTOR_HOST, GESTOR_PORT):
            response = query_user_info(username, receiver)
            if response.get("status") == "success":
                target_ip = response.get("ip")
                update_cached_ip(receiver, target_ip)
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


# region send_message_to_ip
def send_message_to_ip(ip, sender, receiver, message_content):
    """Intenta conectar y enviar un mensaje al destinatario en una IP específica usando dos conexiones."""
    try:
        # Primera conexión: Verificar quién está conectado
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as query_socket:
            query_socket.settimeout(5)
            query_socket.connect((ip, CLIENT_PORT))

            # Enviar solicitud 'who_is_connected'
            who_is_connected = {"action": "who_is_connected"}
            who_json = json.dumps(who_is_connected)

            query_socket.sendall(who_json.encode())
            response_data = query_socket.recv(BUFFER_SIZE).decode()
            response = json.loads(response_data)

            # Validar receptor
            if response.get("username") != receiver:
                print(col(f"El usuario en {ip} no es {receiver}.", "yellow"))
                return False

        # Segunda conexión: Enviar el mensaje
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as message_socket:
            message_socket.settimeout(5)
            message_socket.connect((ip, CLIENT_PORT))

            # Preparar y enviar el mensaje
            message = {
                "sender": sender,
                "content": message_content,
            }
            message_json = json.dumps(message)
            message_socket.sendall(message_json.encode())
            print(col(f"Mensaje entregado a {receiver}: {message_content}", "green"))
            return True

    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        logging.error(
            col(f"Error al intentar conectar con {receiver} en {ip}: {str(e)}", "red")
        )
    except json.JSONDecodeError as e:
        logging.error(col(f"Error al decodificar JSON: {str(e)}", "red"))
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
    # print(col(f"IP cacheada para {username} actualizada a {ip}.", "blue"))

def connect_to_server():
    global SERVER_UP,GESTOR_HOST
    while True:
        time.sleep(5)
        if not is_server_active(GESTOR_HOST, GESTOR_PORT):
            SERVER_UP=False
            try:
                GESTOR_HOST = discover_servers()[0]
                print(col(f"NEW SERVER FOUND {GESTOR_HOST}",'green'))
                SERVER_UP=True
            except Exception as e:
                pass

# region main
def main():
    global GESTOR_HOST, stop_event,loguedout
    threading.Thread(target=connect_to_server, daemon=True).start()
    
    try:
        GESTOR_HOST = discover_servers()[0]
        print(col(f"FOUND SERVER ON:{GESTOR_HOST}",'green'))
    except Exception as e:
        GESTOR_HOST='192.168.1.2'

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
                    if loguedout:
                        loguedout=False
                        break

                    print("\nOpciones disponibles:")
                    print("\t1. Consultar usuario")
                    print("\t2. Enviar mensaje")
                    print("\t3. Ver chats")
                    print("\t4. Abrir un chat")
                    print("\t5. Cerrar sesión")
                    sub_choice = input("Opción: ")
                    
                    if loguedout:
                        loguedout=False
                        break

                    if sub_choice == "1":
                        if is_server_active(GESTOR_HOST, GESTOR_PORT):
                            target_username = input("\tNombre de usuario a consultar: ")
                            response = query_user_info(username, target_username)
                            if response.get("status") == "success":
                                print(col(f"{response.get('ip')}", "magenta"))
                                # print(f"Llave Pública:\n{response.get('public_key')}")
                            else:
                                print(col(f"Error: {response.get('message')}", "red"))
                        else:
                            print(
                                col(
                                    "El servidor se encuentra desconectado. Inténtelo de nuevo mas tarde.",
                                    "red",
                                )
                            )
                    elif sub_choice == "2":
                        send_message(username)
                    elif sub_choice == "3":
                        show_chats()
                    elif sub_choice == "4":
                        open_chat()
                    elif sub_choice == "5":
                        print("Cerrando sesión...")
                        logout()
                        print(col("Sesión cerrada correctamente.", "green"))
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
