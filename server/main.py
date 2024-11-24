import socket
import time

def get_ip():
    try:
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except Exception as e:
        return f"Error obteniendo la IP: {e}"

if __name__ == "__main__":
    while True:
        ip = get_ip()
        print(f"Mi IP en la red Docker es: {ip}")
        time.sleep(60)
