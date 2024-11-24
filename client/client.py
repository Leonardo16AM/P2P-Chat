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


BROADCAST_PORT = 55555  # Puerto para el broadcast
BUFFER_SIZE = 1024      # Tamaño del buffer para recibir mensajes

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
GESTOR_HOST = '127.0.0.1' 
GESTOR_PORT = 65432
ALIVE_INTERVAL = 10  

# Rutas de almacenamiento de llaves
PRIVATE_KEY_FILE = 'private_key.pem'
PUBLIC_KEY_FILE = 'public_key.pem'

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

#region alive
def send_alive_signal(username, public_key_str):
    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((GESTOR_HOST, GESTOR_PORT))
                message = {
                    "action": "alive_signal",
                    "username": username,
                    "public_key": public_key_str
                }
                s.sendall(json.dumps(message).encode())
                response = s.recv(4096)
                response = json.loads(response.decode())
                if response.get("status") != "success":
                    print(f"Error en señal de vida: {response.get('message')}")
        except Exception as e:
            print(f"Error al enviar señal de vida: {str(e)}")
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

#region main
def main():
    GESTOR_HOST=find_gestor()
    print(col(f"Found gestor at: {GESTOR_HOST}",'green'))

    private_key, public_key = load_or_generate_keys()
    public_key_str = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    print(col("Bienvenido al Cliente de Chat P2P",'blue'))
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
            username = input("Nombre de usuario: ")
            password = getpass("Contraseña: ")
            response = login(username, password)
            print(response.get("message"))
            if response.get("status") == "success":
                # Iniciar hilo de señales de vida
                alive_thread = threading.Thread(target=send_alive_signal, args=(username, public_key_str), daemon=True)
                alive_thread.start()
                print("Señales de vida enviándose en segundo plano.")
                # Iniciar interfaz de consultas
                while True:
                    print("\nOpciones disponibles:")
                    print("1. Consultar usuario")
                    print("2. Cerrar Sesión")
                    sub_choice = input("Opción: ")
                    if sub_choice == "1":
                        target_username = input("Nombre de usuario a consultar: ")
                        response = query_user_info(username, target_username)
                        if response.get("status") == "success":
                            print(f"IP: {response.get('ip')}")
                            print(f"Llave Pública:\n{response.get('public_key')}")
                        else:
                            print(f"Error: {response.get('message')}")
                    elif sub_choice == "2":
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
    main()
