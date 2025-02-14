# gestor/main.py
import socket
import threading
import time
import sys
import os
from .config import HOST, SERVER_PORT, CLIENT_PORT
from .logging import log_message
from .db import init_db
from .client_handler import handle_client
# from .server_handler import server_server
from termcolor import colored as col
import json

import server.global_state as gs

#region initialize_global_state
def initialize_global_state():
    # Se obtiene la IP local a partir de la variable de entorno o mediante detección
    local_ip_env = os.environ.get("LOCAL_IP")
    if local_ip_env:
        local_ip_value = local_ip_env
    else:
        local_ip_value = socket.gethostbyname(socket.gethostname())
    gs.local_ip = local_ip_value
    # Se calcula un identificador simple para este nodo (por ejemplo, usando la función hash de Python)
    my_node_id_value = hash(local_ip_value + str(SERVER_PORT)) & 0xffffffff  # 32 bits
    gs.my_node_id = my_node_id_value
    log_message(col(f"Iniciando gestor. IP: {gs.local_ip}, node_id: {gs.my_node_id}",'green'))

#region CHORD server
def chord_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, SERVER_PORT))
    s.listen(5)
    log_message(col(f"[Chord] RPC server listening on {HOST}:{SERVER_PORT}", "cyan"))
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_chord_request, args=(conn, addr), daemon=True).start()

def handle_chord_request(conn, addr):
    try:
        data = conn.recv(4096)
        if data:
            request = json.loads(data.decode())
            from .ring import chord_handler
            response = chord_handler(request)
            conn.sendall(json.dumps(response).encode())
    except Exception as e:
        log_message(col(f"[Chord] Error procesando petición de {addr}: {e}", "red"))
    finally:
        conn.close()

# region Client server 
def client_server():
    client_port = CLIENT_PORT
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, client_port))
    s.listen(5)
    log_message(col(f"[Client] Server listening on {HOST}:{client_port}", "cyan"))
    while True:
        conn, addr = s.accept()
        log_message(col(f"[Client] Received connection from {addr}", "green"))
        # Se delega la gestión de la conexión a la función handle_client_request
        threading.Thread(target=handle_client_request, args=(conn, addr), daemon=True).start()

def handle_client_request(conn, addr):
    try:
        # Reutilizamos la función handle_client definida en client_handler.py
        handle_client(conn, addr)
    except Exception as e:
        log_message(col(f"[Client] Error al procesar petición de {addr}: {e}", "red"))

#region main
def main():
    print("______________________________________________________________")
    initialize_global_state()
    init_db()

    
    from .ring import join, start_chord_maintenance,ring_init
    # Si se proporciona la variable de entorno JOIN_NODE (formato ip:puerto),
    # se une a un anillo existente. De lo contrario, se arranca un anillo nuevo.
    join_node = os.environ.get("JOIN_NODE")
    ring_init()
    if join_node:
        try:
            ip, port_str = join_node.split(":")
            port = int(port_str)
            existing_node = {"id": None, "ip": ip, "port": port}
            join(existing_node)
            log_message(col(f"[Chord] Nodo unido al anillo a través de {ip}:{port}", "green"))
        except Exception as e:
            log_message(col(f"[Chord] Error al parsear JOIN_NODE: {e}. Arrancando anillo nuevo.", "red"))
    else:
        log_message(col("[Chord] Iniciado anillo nuevo. Este es el primer nodo.", "green"))

    start_chord_maintenance()
    threading.Thread(target=chord_server, daemon=True).start()

    # Lanzamos en paralelo el servidor para atender peticiones de clientes
    threading.Thread(target=client_server, daemon=True).start()


    # Lanzar hilos de escucha
    # threading.Thread(target=client_server, args=(['192.168.1.2'],), daemon=True).start()
    # threading.Thread(target=server_server, daemon=True).start()
    # threading.Thread(target=ring_update_sender, daemon=True).start()
    # threading.Thread(target=find_if_duplicates_are_alive, daemon=True).start()
    # # Bucle principal para mantener vivo el proceso
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log_message(col("Gestor finalizado por teclado.",'red'))
        sys.exit(0)

if __name__ == "__main__":
    main()
