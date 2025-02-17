# gestor/main.py
import socket
import threading
import time
import sys
import os
from typing import Tuple
from .config import HOST, SERVER_PORT, CLIENT_PORT
from .logging import log_message
from .db import init_db
from .client_handler import handle_client, cleanup_users
from termcolor import colored as col
import json
import struct

import server.global_state as gs


# region initialize_global_state
def initialize_global_state() -> None:
    """
    Initializes the global state for the server application.
    """
    local_ip_env = os.environ.get("LOCAL_IP")
    if local_ip_env:
        local_ip_value = local_ip_env
    else:
        local_ip_value = socket.gethostbyname(socket.gethostname())
    gs.local_ip = local_ip_value
    my_node_id_value = hash(local_ip_value + str(SERVER_PORT)) & 0xFFFFFFFF  # 32 bits
    gs.my_node_id = my_node_id_value
    log_message(
        col(f"Iniciando gestor. IP: {gs.local_ip}, node_id: {gs.my_node_id}", "green")
    )


# region CHORD server
def chord_server() -> None:
    """
    Starts a Chord RPC server that listens for incoming connections to handle chord requests.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, SERVER_PORT))
    s.listen(5)
    log_message(col(f"[Chord] RPC server listening on {HOST}:{SERVER_PORT}", "cyan"))
    while True:
        conn, addr = s.accept()
        threading.Thread(
            target=handle_chord_request, args=(conn, addr), daemon=True
        ).start()


def handle_chord_request(conn: socket.socket, addr: Tuple[str, int]) -> None:
    """
    Handles a chord protocol request from a client.
    """
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
def client_server() -> None:
    """
    Creates a TCP server socket that listens for client connections and spawns a new thread to handle each request.
    """
    client_port = CLIENT_PORT
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, client_port))
    s.listen(5)
    log_message(col(f"[Client] Server listening on {HOST}:{client_port}", "cyan"))
    while True:
        conn, addr = s.accept()
        threading.Thread(
            target=handle_client_request, args=(conn, addr), daemon=True
        ).start()


# region handle_client_request
def handle_client_request(conn: socket.socket, addr: Tuple[str, int]) -> None:
    """
    Handles a client request by invoking the handle_client function and logging any exceptions that occur.
    """
    try:
        handle_client(conn, addr)
    except Exception as e:
        log_message(col(f"[Client] Error al procesar petición de {addr}: {e}", "red"))


# region multicast_listener
def multicast_listener() -> None:
    """
    Function that listens for multicast requests.
    When it receives the DISCOVER_SERVER message, it responds with its IP address.
    """
    MCAST_GRP = "224.0.0.1"
    MCAST_PORT = 10003
    DISCOVER_MSG = "DISCOVER_SERVER"
    BUFFER_SIZE = 1024
    # Crear socket UDP
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    # Permitir que varias instancias puedan reutilizar el puerto
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Vincular el socket a todas las interfaces en el puerto MCAST_PORT
    sock.bind(("", MCAST_PORT))

    # Unirse al grupo multicast
    mreq = struct.pack("=4sl", socket.inet_aton(MCAST_GRP), socket.INADDR_ANY)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    log_message(
        col(f"[Muticast] Escuchando mensajes en {MCAST_GRP}:{MCAST_PORT}", "magenta")
    )

    while True:
        try:
            data, addr = sock.recvfrom(BUFFER_SIZE)
            message = data.decode().strip()
            print(f"Recibido mensaje: '{message}' desde {addr}")
            if message.startswith(DISCOVER_MSG + ":"):
                local_ip = gs.local_ip
                _, rec_ip, rec_port = message.split(":")
                print(f"{rec_ip} {rec_port}")
                sock.sendto(local_ip.encode(), (rec_ip, int(rec_port)))
            else:
                local_ip = gs.local_ip
                sock.sendto(local_ip.encode(), addr)
        except Exception as e:
            print(f"Error en el listener: {e}")
            time.sleep(1)


# region discover_servers
def discover_servers(timeout: str = 1) -> list:
    """
    Sends a multicast request to discover servers and waits for responses.

    :param timeout: Maximum time (in seconds) to wait for responses.
    :return: List of IPs of the discovered servers.
    """
    MCAST_GRP = "224.0.0.1"
    MCAST_PORT = 10003
    MESSAGE = "DISCOVER_SERVER"
    BUFFER_SIZE = 1024

    # Crear socket UDP para enviar y recibir
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(timeout)

    # Configurar TTL del paquete multicast
    ttl = struct.pack("b", 1)
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
            log_message(col(f"Servidor descubierto: {server_ip}", "green"))
        except socket.timeout:
            break
        except Exception as e:
            print(f"Error recibiendo datos: {e}")
            break
        if time.time() - start_time > timeout:
            break

    sock.close()
    return servers


# region main
def main() -> None:
    """
    Main entry point for the server application.

    This function performs the following operations:
    1. Prints a decorative separator line.
    2. Initializes the global state and the database.
    3. Imports necessary functions from the ring module and initializes the chord ring.
    4. Attempts to join an existing chord ring:
        - Discovers a server using discover_servers to get the IP.
        - Constructs the node information and tries to join the ring.
        - Logs a success message on joining, or if joining fails, logs that a new ring is being initiated.
    5. Starts chord maintenance routines.
    6. Launches several daemon threads to handle:
        - Multicast message listening.
        - Chord server operations.
        - Client server operations.
        - Cleanup of inactive users.
    7. Enters an infinite loop, periodically sleeping until a KeyboardInterrupt is received, at which point:
        - Logs a shutdown message.
        - Exits the application gracefully.

    Raises:
         SystemExit: When a KeyboardInterrupt is caught, the application terminates.
    """
    print(
        "________________________________________________________________________________"
    )
    initialize_global_state()
    init_db()

    from .ring import join, start_chord_maintenance, ring_init

    ring_init()
    try:
        ip = discover_servers()[0]
        port = SERVER_PORT
        existing_node = {"id": None, "ip": ip, "port": port}
        join(existing_node)
        log_message(
            col(f"[Chord] Nodo unido al anillo a través de {ip}:{port}", "green")
        )
    except Exception as e:
        log_message(
            col("[Chord] Iniciado anillo nuevo. Este es el primer nodo:{e}", "green")
        )

    start_chord_maintenance()

    threading.Thread(target=multicast_listener, daemon=True).start()
    threading.Thread(target=chord_server, daemon=True).start()
    threading.Thread(target=client_server, daemon=True).start()
    threading.Thread(target=cleanup_users, daemon=True).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log_message(col("Gestor finalizado por teclado.", "red"))
        sys.exit(0)


if __name__ == "__main__":
    main()
