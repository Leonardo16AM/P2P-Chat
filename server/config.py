# gestor/config.py
import os

# Host y puertos
HOST = "0.0.0.0"
CLIENT_PORT = 65434  # Para la comunicación con clientes
SERVER_PORT = 65433  # Para la comunicación entre gestores
TIMEOUT = 20

VERBOSE = True
NUM_OF_REPLICAS = 2

# Intervalos (en segundos)
ALIVE_INTERVAL = 1
RING_UPDATE_INTERVAL = 5
FIX_FINGERS_INTERVAL = 5
CHECK_PREDECESSOR_INTERVAL = 2
CHECK_SUCCESSOR_INTERVAL = 2
CHECK_DUPLICATES_INTERVAL = 10
TIMEOUT = 500

# Archivos de base de datos y log
DB_FILE = os.path.join(os.path.dirname(__file__), "gestor.db")
LOG_FILE = os.path.join(os.path.dirname(__file__), "gestor.log")
