# gestor/config.py
import os

# Host y puertos
HOST = "0.0.0.0"
CLIENT_PORT = 65432       # Para la comunicación con clientes
SERVER_PORT = 65433       # Para la comunicación entre gestores

# Intervalos (en segundos)
ALIVE_INTERVAL = 1
RING_UPDATE_INTERVAL = 5
FIX_FINGERS_INTERVAL = 5
CHECK_PREDECESSOR_INTERVAL=5
CHECK_SUCCESSOR_INTERVAL=5
CHECK_DUPLICATES_INTERVAL = 10
TIMEOUT = 5

# Archivos de base de datos y log
DB_FILE = os.path.join(os.path.dirname(__file__), "gestor.db")
LOG_FILE = os.path.join(os.path.dirname(__file__), "gestor.log")
