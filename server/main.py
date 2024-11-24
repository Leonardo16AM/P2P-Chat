import socket
import time
import threading

BROADCAST_PORT = 55555  # Puerto para escuchar solicitudes de broadcast
BUFFER_SIZE = 1024      # Tamaño del buffer para recibir mensajes

def get_ip():
    """Obtiene la dirección IP local."""
    try:
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except Exception as e:
        return f"Error obteniendo la IP: {e}"

def broadcast_responder():
    """Responde a solicitudes de broadcast con la IP del gestor."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Reutilizar dirección
        s.bind(("", BROADCAST_PORT))  # Escuchar en cualquier dirección

        print(f"Esperando solicitudes de broadcast en el puerto {BROADCAST_PORT}...")

        while True:
            try:
                data, addr = s.recvfrom(BUFFER_SIZE)
                if data.decode() == "DISCOVER_GESTOR":
                    gestor_ip = get_ip()
                    s.sendto(gestor_ip.encode(), addr)
                    print(f"Respondido con IP {gestor_ip} a {addr}")
            except Exception as e:
                print(f"Error en broadcast_responder: {e}")

if __name__ == "__main__":
    # Iniciar responder de broadcast en un hilo separado
    responder_thread = threading.Thread(target=broadcast_responder, daemon=True)
    responder_thread.start()

    print("Servidor gestor en ejecución. Presiona Ctrl+C para salir.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Servidor detenido.")
    while True:
        ip = get_ip()
        print(f"Mi IP en la red Docker es: {ip}")
        time.sleep(60)
