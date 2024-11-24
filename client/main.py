import socket
import time

BROADCAST_PORT = 55555  # Puerto para el broadcast
BUFFER_SIZE = 1024      # Tamaño del buffer para recibir mensajes

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
            print("Enviando broadcast para descubrir gestor...")
            s.sendto(broadcast_message, ('<broadcast>', BROADCAST_PORT))

            # Esperar respuesta
            data, addr = s.recvfrom(BUFFER_SIZE)
            gestor_ip = data.decode()
            print(f"Gestor descubierto en {gestor_ip} (desde {addr})")
        except socket.timeout:
            print("No se recibió respuesta del gestor.")
        except Exception as e:
            print(f"Error al buscar el gestor: {e}")
        return gestor_ip


if __name__ == "__main__":
    gestor_ip = find_gestor()
    if gestor_ip:
        print(f"Gestor encontrado en {gestor_ip}")
    else:
        print("No se pudo encontrar el gestor.")
    while True:
        ip = get_ip()
        print(f"Mi IP en la red Docker es: {ip}")
        time.sleep(60)
