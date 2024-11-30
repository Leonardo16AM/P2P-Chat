import socket
import time
import threading
import logging

BROADCAST_PORT = 55555  # Puerto para escuchar solicitudes de broadcast
BUFFER_SIZE = 1024  # Tamaño del buffer para recibir mensajes

# Configuración del logging
logging.basicConfig(
    filename="locator.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)


def get_ip():
    """Obtiene la dirección IP local."""
    try:
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except Exception as e:
        logging.error(f"Error obteniendo la IP: {e}")
        return f"Error obteniendo la IP: {e}"


def broadcast_answer():
    """Responde a solicitudes de broadcast con la IP del gestor."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Reutilizar dirección
        s.bind(("", BROADCAST_PORT))  # Escuchar en cualquier dirección

        logging.info(
            f"Esperando solicitudes de broadcast en el puerto {BROADCAST_PORT}..."
        )

        while True:
            try:
                data, addr = s.recvfrom(BUFFER_SIZE)
                if data.decode() == "DISCOVER_GESTOR":
                    gestor_ip = get_ip()
                    s.sendto(gestor_ip.encode(), addr)
                    logging.info(f"Respondido con IP {gestor_ip} a {addr}")
            except Exception as e:
                logging.error(f"Error on broadcast_answer: {e}")


if __name__ == "__main__":
    answerer_thread = threading.Thread(target=broadcast_answer, daemon=True)
    answerer_thread.start()

    logging.info("Gestor Locator en ejecución")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Servidor detenido.")
    while True:
        ip = get_ip()
        logging.info(f"Mi IP en la red Docker es: {ip}")
        time.sleep(60)
