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


BROADCAST_PORT = 55555  # Puerto para el broadcast
BUFFER_SIZE = 1024      # Tamaño del buffer para recibir mensajes
DB_FILE = "client_data.db"  # Nombre del archivo de la base de datos
CLIENT_PORT = 12345


logging.basicConfig(filename='client.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

 
def find_gestor():
    """Descubre la dirección IP del gestor mediante broadcast."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)  # Activar modo broadcast
        s.settimeout(5)  # Tiempo de espera por respuesta

        broadcast_message = b"DISCOVER_GESTOR"
        gestor_ip = None

        try:
            logging.info("Enviando broadcast para descubrir gestor...")
            s.sendto(broadcast_message, ('<broadcast>', BROADCAST_PORT))

            # Esperar respuesta
            data, addr = s.recvfrom(BUFFER_SIZE)
            gestor_ip = data.decode()
            logging.info(f"Gestor descubierto en {gestor_ip} (desde {addr})")
        except socket.timeout:
            logging.warning("No se recibió respuesta del gestor.")
        except Exception as e:
            logging.error(f"Error al buscar el gestor: {e}")
        return gestor_ip


# Configuración
GESTOR_HOST = '192.168.1.2' 
GESTOR_PORT = 65432
ALIVE_INTERVAL = 10  

# Rutas de almacenamiento de llaves
PRIVATE_KEY_FILE = 'private_key.pem'
PUBLIC_KEY_FILE = 'public_key.pem'

#region lock

LOCK_FILE = 'client.lock'

def check_single_instance():
    if os.path.exists(LOCK_FILE):
        print("Otra instancia del cliente ya está en ejecución.")
        sys.exit()
    else:
        with open(LOCK_FILE, 'w') as f:
            f.write('lock')

def remove_lock():
    if os.path.exists(LOCK_FILE):
        os.remove(LOCK_FILE)


#region keys
def load_or_generate_keys():
    if os.path.exists(PRIVATE_KEY_FILE) and os.path.exists(PUBLIC_KEY_FILE):
        with open(PRIVATE_KEY_FILE, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        with open(PUBLIC_KEY_FILE, "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
        print("Llaves RSA cargadas exitosamente.")
    else:
        print("Generando nuevas llaves RSA...")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        # Guardar las llaves en archivos
        with open(PRIVATE_KEY_FILE, "wb") as key_file:
            key_file.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )
        with open(PUBLIC_KEY_FILE, "wb") as key_file:
            key_file.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )
        print("Llaves RSA generadas y almacenadas exitosamente.")
    return private_key, public_key

#region register
def register(username, password, public_key_str):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((GESTOR_HOST, GESTOR_PORT))
            message = {
                "action": "register",
                "username": username,
                "password": password,
                "public_key": public_key_str
            }
            s.sendall(json.dumps(message).encode())
            response = s.recv(4096)
            response = json.loads(response.decode())
            return response
    except Exception as e:
        return {"status": "error", "message": f"Error de conexión: {str(e)}"}

#region login
def login(username, password):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((GESTOR_HOST, GESTOR_PORT))
            message = {
                "action": "login",
                "username": username,
                "password": password
            }
            s.sendall(json.dumps(message).encode())
            response = s.recv(4096)
            response = json.loads(response.decode())
            return response
    except Exception as e:
        return {"status": "error", "message": f"Error de conexión: {str(e)}"}
    
#region logout

def logout():
    """Gestiona el cierre de sesión."""
    stop_all_threads()  # Detener los hilos activos
    global username
    username = None
    print(col("Sesión cerrada correctamente.", 'green'))



stop_event = threading.Event()

def stop_all_threads():
    """Detiene todos los hilos en ejecución."""
    stop_event.set()
    print(col("Hilos detenidos.", 'yellow'))


#region alive
# def send_alive_signal(username, public_key_str):
#     global GESTOR_HOST 
#     while True:
#         try:
#             with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
#                 s.connect((GESTOR_HOST, GESTOR_PORT))
#                 message = {
#                     "action": "alive_signal",
#                     "username": username,
#                     "public_key": public_key_str
#                 }
#                 s.sendall(json.dumps(message).encode())
#                 response = s.recv(4096)
#                 response = json.loads(response.decode())
#                 if response.get("status") != "success":
#                     print(f"Error en señal de vida: {response.get('message')}")
#         except Exception as e:
#             print(f"Error al enviar señal de vida: {str(e)}")
#             while True:
#                 gestor_ip = find_gestor()
#                 if gestor_ip:
#                     GESTOR_HOST = gestor_ip  
#                     print(col(f"Nuevo gestor encontrado: {GESTOR_HOST}", 'green'))
#                     break  
#                 else:
#                     print("Gestor no encontrado. Reintentando en 5 segundos...")
#                     time.sleep(5)  
#         time.sleep(ALIVE_INTERVAL)

# def send_alive_signal(username, public_key_str):
#     global GESTOR_HOST
#     while not stop_event.is_set():
#         try:
#             with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
#                 s.connect((GESTOR_HOST, GESTOR_PORT))
#                 message = {
#                     "action": "alive_signal",
#                     "username": username,
#                     "public_key": public_key_str
#                 }
#                 s.sendall(json.dumps(message).encode())
#         except Exception as e:
#             print(f"Error al enviar señal de vida: {str(e)}")
#         time.sleep(ALIVE_INTERVAL)

def send_alive_signal(username, public_key_str):
    global GESTOR_HOST
    while not stop_event.is_set():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((GESTOR_HOST, GESTOR_PORT))
                message = {
                    "action": "alive_signal",
                    "username": username,
                    "public_key": public_key_str
                }
                s.sendall(json.dumps(message).encode())
        except Exception as e:
            print(col(f"Error al enviar señal de vida: {str(e)}", 'red'))
            # Si falla, reintentar localizar el gestor
            GESTOR_HOST = find_gestor()
            if not GESTOR_HOST:
                print(col("No se encontró gestor, reintentando en 5 segundos.", 'red'))
                time.sleep(5)
        time.sleep(ALIVE_INTERVAL)




#region user_query
def query_user_info(username, target_username):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((GESTOR_HOST, GESTOR_PORT))
            message = {
                "action": "get_user",
                "username": username,
                "target_username": target_username
            }
            s.sendall(json.dumps(message).encode())
            response = s.recv(4096)
            response = json.loads(response.decode())
            return response
    except Exception as e:
        return {"status": "error", "message": f"Error de conexión: {str(e)}"}
    
# region database
    
def initialize_database():
    """Crea la base de datos SQLite y las tablas necesarias."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Tabla para almacenar usuarios
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            public_key TEXT NOT NULL
        );
    ''')    
    
    # Tabla para almacenar mensajes
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_id INTEGER NOT NULL,     -- Relación con el chat
        sender TEXT NOT NULL,         -- Quién envió el mensaje (yo o el usuario remoto)
        message TEXT NOT NULL,        -- Contenido del mensaje
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        delivered INTEGER DEFAULT 0,  -- 0 = No entregado, 1 = Entregado
        FOREIGN KEY(chat_id) REFERENCES chats(id) ON DELETE CASCADE
    );
    ''')
    
    # Tabla para almacenar historial de chats (si es necesario)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS chats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,       -- Usuario remoto
        last_message TEXT,            -- Último mensaje del chat
        last_timestamp DATETIME,      -- Timestamp del último mensaje
        UNIQUE(username)              -- Un chat por usuario
    );
    ''')
    
    conn.commit()
    conn.close()
    print("Base de datos inicializada correctamente.")

# region chat

# def save_message(sender, receiver, message, delivered=False):
#     """Guarda un mensaje en la base de datos."""
#     conn = sqlite3.connect(DB_FILE)
#     cursor = conn.cursor()
#     cursor.execute('''
#         INSERT INTO messages (sender, receiver, message, delivered)
#         VALUES (?, ?, ?, ?)
#     ''', (sender, receiver, message, 1 if delivered else 0))
#     conn.commit()
#     conn.close()

def save_message(chat_id, sender, message, delivered=False):
    """Guarda un mensaje en la base de datos."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Insertar el mensaje
    cursor.execute('''
        INSERT INTO messages (chat_id, sender, message, delivered)
        VALUES (?, ?, ?, ?)
    ''', (chat_id, sender, message, 1 if delivered else 0))
    
    # Actualizar el último mensaje del chat
    cursor.execute('''
        UPDATE chats
        SET last_message = ?, last_timestamp = CURRENT_TIMESTAMP
        WHERE id = ?
    ''', (message, chat_id))
    
    conn.commit()
    conn.close()
    
def get_chat_messages(chat_id):
    """Obtiene los mensajes de un chat."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT sender, message, timestamp
        FROM messages
        WHERE chat_id = ?
        ORDER BY timestamp ASC
    ''', (chat_id,))
    messages = cursor.fetchall()
    conn.close()
    return messages

def list_chats():
    """Lista todos los chats activos."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, username, last_message, last_timestamp
        FROM chats
        ORDER BY last_timestamp DESC
    ''')
    chats = cursor.fetchall()
    conn.close()
    return chats

def show_chats():
    """Muestra una lista de los chats activos."""
    chats = list_chats()
    if not chats:
        print(col("No tienes chats activos.", 'yellow'))
        return
    
    print(col("Chats activos:", 'blue'))
    for chat in chats:
        chat_id, username, last_message, last_timestamp = chat
        print(f"{chat_id}: {username} - Último mensaje: '{last_message}' a las {last_timestamp}")


def get_pending_messages(chat_id):
    """Obtiene mensajes no entregados para un chat específico."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, sender, message, timestamp FROM messages
        WHERE chat_id = ? AND delivered = 0
    ''', (chat_id,))
    messages = cursor.fetchall()
    conn.close()
    return messages

def review_pending_messages():
    """Revisa los mensajes pendientes almacenados localmente para todos los chats."""
    chats = list_chats()
    if not chats:
        print(col("No tienes mensajes pendientes.", 'green'))
        return
    
    print(col("Revisando mensajes pendientes...", 'blue'))
    for chat in chats:
        chat_id, username, last_message, last_timestamp = chat
        pending_messages = get_pending_messages(chat_id)
        if not pending_messages:
            continue
        
        print(col(f"\nChat con {username}:", 'cyan'))
        for msg in pending_messages:
            print(f"[Pendiente] {col(msg[1], 'cyan')}: {msg[2]} (enviado el {msg[3]})")
        
        # Marcar como entregados
        message_ids = [msg[0] for msg in pending_messages]
        mark_messages_as_delivered(message_ids)




def get_or_create_chat(username):
    """Obtiene o crea un chat con un usuario."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Buscar el chat existente
    cursor.execute('''
        SELECT id FROM chats WHERE username = ?
    ''', (username,))
    chat = cursor.fetchone()
    
    # Si no existe, crear uno
    if chat is None:
        cursor.execute('''
            INSERT INTO chats (username, last_message, last_timestamp)
            VALUES (?, ?, ?)
        ''', (username, None, None))
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
            print(col("No hay mensajes en este chat.", 'yellow'))
            return
        
        print(col("Mensajes:", 'blue'))
        for sender, message, timestamp in messages:
            print(f"[{timestamp}] {col(sender, 'cyan')}: {message}")
    except ValueError:
        print(col("ID del chat no válido.", 'red'))




def mark_messages_as_delivered(message_ids):
    """Marca mensajes como entregados en la base de datos."""
    if not message_ids:
        print("No hay mensajes pendientes para marcar como entregados.")
        return

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE messages
        SET delivered = 1
        WHERE id IN ({})
    '''.format(','.join('?' for _ in message_ids)), message_ids)
    conn.commit()
    conn.close()
    print(f"Mensajes marcados como entregados: {message_ids}")


def send_message(username):
    """Envía un mensaje a otro usuario."""
    target_username = input("Usuario destino: ")
    message_content = input("Mensaje: ")

    # Obtener o crear el chat
    chat_id = get_or_create_chat(target_username)
    
    # Consultar al gestor para obtener la IP del destinatario
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
                print(col("Mensaje enviado con éxito.", 'green'))
                save_message(chat_id, username, message_content, delivered=True)
        except Exception as e:
            print(col(f"Error al enviar el mensaje: {str(e)}", 'red'))
            save_message(chat_id, username, message_content, delivered=False)
    else:
        print(col(f"Error al obtener información del usuario: {response.get('message')}", 'red'))



# def start_message_listener(username):
#     """Inicia un servidor para recibir mensajes de otros usuarios."""
#     def listen():
#         with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
#             server_socket.bind(('', CLIENT_PORT))
#             server_socket.listen(5)  # Escuchar hasta 5 conexiones simultáneas
#             print(col(f"[{username}] Escuchando mensajes en el puerto {CLIENT_PORT}...", 'green'))
            
#             while True:
#                 conn, addr = server_socket.accept()
#                 with conn:
#                     try:
#                         # Recibir datos del socket
#                         message_data = conn.recv(BUFFER_SIZE).decode()
#                         message_json = json.loads(message_data)  # Convertir de JSON a diccionario

#                         # Extraer información del mensaje
#                         sender = message_json.get("sender")
#                         content = message_json.get("content")

#                         # Validar campos obligatorios
#                         if not sender or not content:
#                             print(col(f"Mensaje inválido recibido de {addr[0]}", 'red'))
#                             continue
                        
#                         # Mostrar mensaje recibido
#                         print(col(f"Nuevo mensaje de {sender}: {content}", 'cyan'))
                        
#                         # Obtener o crear el chat con el remitente
#                         chat_id = get_or_create_chat(sender)
                        
#                         # Guardar el mensaje en la base de datos
#                         save_message(chat_id, sender, content, delivered=True)
#                     except json.JSONDecodeError:
#                         print(col(f"Error al decodificar el mensaje de {addr[0]}", 'red'))
#                     except Exception as e:
#                         print(col(f"Error al procesar mensaje de {addr[0]}: {str(e)}", 'red'))

#     # Ejecutar el servidor en un hilo separado
#     listener_thread = threading.Thread(target=listen, daemon=True)
#     listener_thread.start()


listener_thread = None

def start_message_listener(username):
    global listener_thread
    def listen():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Permitir reutilización del puerto
            server_socket.bind(('', CLIENT_PORT))
            server_socket.listen(5)
            print(col(f"[{username}] Escuchando mensajes en el puerto {CLIENT_PORT}...", 'green'))
            
            while not stop_event.is_set():
                conn, addr = server_socket.accept()
                with conn:
                    try:
                        message_data = conn.recv(BUFFER_SIZE).decode()
                        message_json = json.loads(message_data)
                        sender = message_json.get("sender")
                        content = message_json.get("content")
                        if sender and content:
                            print(col(f"Nuevo mensaje de {sender}: {content}", 'cyan'))
                    except Exception as e:
                        print(col(f"Error al procesar mensaje: {str(e)}", 'red'))

    if listener_thread and listener_thread.is_alive():
        print(col("Listener ya está corriendo.", 'yellow'))
        return

    listener_thread = threading.Thread(target=listen, daemon=True)
    listener_thread.start()




#region main
def main():
    global GESTOR_HOST, stop_event

    GESTOR_HOST = find_gestor()
    print(col(f"Gestor encontrado en: {GESTOR_HOST}", 'green'))

    private_key, public_key = load_or_generate_keys()
    public_key_str = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    print(col("Bienvenido al Cliente de Chat P2P", 'blue'))
    while True:
        print("\nSelecciona una opción:")
        print("1. Registrarse")
        print("2. Iniciar Sesión")
        print("3. Salir")
        choice = input("Opción: ")

        if choice == "1":
            username = input("Nombre de usuario: ")
            password = getpass("Contraseña: ")
            confirm_password = getpass("Confirmar Contraseña: ")
            if password != confirm_password:
                print("Las contraseñas no coinciden. Intenta nuevamente.")
                continue
            response = register(username, password, public_key_str)
            print(response.get("message"))
            if response.get("status") == "success":
                print("Puedes ahora iniciar sesión.")
        elif choice == "2":
            # Iniciar sesión
            username = input("Nombre de usuario: ")
            password = getpass("Contraseña: ")
            response = login(username, password)
            print(response.get("message"))
            if response.get("status") == "success":
                stop_event.clear()  # Reinicia el evento de hilos
                review_pending_messages()
                start_message_listener(username)

                alive_thread = threading.Thread(target=send_alive_signal, args=(username, public_key_str), daemon=True)
                alive_thread.start()

                while True:
                    print("\nOpciones disponibles:")
                    print("1. Consultar usuario")
                    print("2. Enviar mensaje")
                    print("3. Ver chats")
                    print("4. Abrir un chat")
                    print("5. Cerrar sesión")
                    sub_choice = input("Opción: ")

                    if sub_choice == "1":
                        # Consulta de usuario
                        target_username = input("Nombre de usuario a consultar: ")
                        response = query_user_info(username, target_username)
                        if response.get("status") == "success":
                            print(f"IP: {response.get('ip')}")
                            print(f"Llave Pública:\n{response.get('public_key')}")
                        else:
                            print(f"Error: {response.get('message')}")
                    elif sub_choice == "2":
                        # Enviar mensaje
                        send_message(username)
                    elif sub_choice == "3":
                        show_chats()
                    elif sub_choice == "4":
                        open_chat()
                    elif sub_choice == "5":
                        # Cerrar sesión
                        print("Cerrando sesión...")
                        break
                    else:
                        print("Opción no válida. Intenta nuevamente.")

        elif choice == "3":
            print("Saliendo del cliente. ¡Hasta luego!")
            break
        else:
            print("Opción no válida. Intenta nuevamente.")

if __name__ == "__main__":
    check_single_instance()
    try:
        initialize_database()
        main()
    finally:
        remove_lock()




# def main():
#     global GESTOR_HOST, stop_event

#     GESTOR_HOST = find_gestor()
#     print(col(f"Gestor encontrado en: {GESTOR_HOST}", 'green'))

#     private_key, public_key = load_or_generate_keys()
#     public_key_str = public_key.public_bytes(
#         encoding=serialization.Encoding.PEM,
#         format=serialization.PublicFormat.SubjectPublicKeyInfo
#     ).decode()

#     print(col("Bienvenido al Cliente de Chat P2P", 'blue'))
#     while True:
#         print("\nSelecciona una opción:")
#         print("1. Registrarse")
#         print("2. Iniciar Sesión")
#         print("3. Salir")
#         choice = input("Opción: ")

#         if choice == "1":
#             # Registro
#             ...
#         elif choice == "2":
#             # Iniciar sesión
#             username = input("Nombre de usuario: ")
#             password = getpass("Contraseña: ")
#             response = login(username, password)
#             print(response.get("message"))
#             if response.get("status") == "success":
#                 stop_event.clear()  # Reinicia el evento de hilos
#                 review_pending_messages()
#                 start_message_listener(username)

#                 alive_thread = threading.Thread(target=send_alive_signal, args=(username, public_key_str), daemon=True)
#                 alive_thread.start()

#                 while True:
#                     print("\nOpciones disponibles:")
#                     print("1. Consultar usuario")
#                     print("2. Enviar mensaje")
#                     print("3. Ver chats")
#                     print("4. Abrir un chat")
#                     print("5. Cerrar sesión")
#                     sub_choice = input("Opción: ")

#                     if sub_choice == "1":
#                         # Consultar usuario
#                         ...
#                     elif sub_choice == "2":
#                         # Enviar mensaje
#                         ...
#                     elif sub_choice == "3":
#                         # Ver chats
#                         ...
#                     elif sub_choice == "4":
#                         # Abrir chat
#                         ...
#                     elif sub_choice == "5":
#                         # Cerrar sesión
#                         logout()
#                         break
#         elif choice == "3":
#             print("Saliendo del cliente. ¡Hasta luego!")
#             break
