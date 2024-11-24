import socket
import time
import threading
import logging

BROADCAST_PORT = 55555  # Puerto para el broadcast
BUFFER_SIZE = 1024      # Tamaño del buffer para recibir mensajes

logging.basicConfig(filename='client.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

def get_ip():
    """Obtiene la dirección IP local."""
    try:
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except Exception as e:
        return f"Error obteniendo la IP: {e}"
    
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


if __name__ == "__main__":
    while True:
        gestor_ip = find_gestor()
        if gestor_ip:
            logging.info(f"Gestor encontrado en {gestor_ip}")
        else:
            logging.warning("No se pudo encontrar el gestor.")
        
        ip = get_ip()
        logging.info(f"Mi IP en la red Docker es: {ip}")
        time.sleep(60)
