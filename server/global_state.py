# gestor/global_state.py
# Variables globales para compartir estado entre módulos
initial_managers = {}  # Diccionario con gestores conocidos
my_node_id = None  # Identificador de este gestor
local_ip = None  # IP local del nodo
import threading

db_lock = threading.Lock()
