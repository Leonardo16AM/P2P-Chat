# gestor/ring.py
import socket
import time
import json
import random
from termcolor import colored
from .logging import log_message
from .config import (
    VERBOSE,
    DB_FILE,
    SERVER_PORT,
    RING_UPDATE_INTERVAL,
    TIMEOUT,
    FIX_FINGERS_INTERVAL,
    CHECK_PREDECESSOR_INTERVAL,
    CHECK_SUCCESSOR_INTERVAL,
    NUM_OF_REPLICAS,
)
import server.global_state as gs
import sqlite3
import threading

finger_table = []
predecessor = None
successor = None
current = None
connected = 0
M = 32
events = set()
update_ring_lock = False


# region rint
def rint() -> int:
    """
    Returns a random integer between 1 and 10^9.
    """
    return random.randint(1, 1000000000)


# region print_list
def print_list(lista: list, color: str) -> None:
    """
    Prints a list of items in a colored box format.

    Args:
        lista (list): The list of items to be printed.
        color (str): The color to be used for the box and text.

    Returns:
        None
    """
    if not lista:
        return

    max_len = max(len(str(item)) for item in lista)
    box_width = max_len + 4
    print(colored("┌" + "─" * (box_width - 2) + "┐", color))

    for item in lista:
        item_str = str(item)
        padding = " " * (box_width - 3 - len(item_str))
        print(colored("│ " + item_str + padding + "│", color))

    print(colored("└" + "─" * (box_width - 2) + "┘", color))


# region print_db
def print_db() -> None:
    """
    Fetches and prints the current state of the users and backups tables from the database.

    The function performs the following steps:
    1. Acquires a lock to ensure thread-safe access to the database.
    2. Connects to the SQLite database and retrieves data from the 'users' and 'backups' tables.
    3. Formats the retrieved data into tables.
    4. Prints the formatted tables with colored borders and headers.

    The printed tables include:
    - Users table with columns: "Usuario", "IP", "Status"
    - Backups table with columns: "Usuario", "IP", "Status", "Node ID"

    Note:
    - The function uses the `colored` function to print colored text.
    - The function assumes the existence of a global `gs.db_lock` for thread safety and a `DB_FILE` constant for the database file path.
    """
    with gs.db_lock:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT username, ip, status FROM users")
        users = cursor.fetchall()
        cursor.execute("SELECT username, ip, status, node_id FROM backups")
        backups = cursor.fetchall()
        conn.close()

    users_table = []
    users_table.append(["Usuario", "IP", "Status"])
    for username, ip, status in users:
        users_table.append([username, ip, status])

    backups_table = []
    backups_table.append(["Usuario", "IP", "Status", "Node ID"])
    for username, ip, status, node_id in backups:
        backups_table.append([username, ip, status, node_id])

    def print_section(table_data, color):
        col_widths = [
            max(len(str(row[i])) for row in table_data)
            for i in range(len(table_data[0]))
        ]
        row_format = (
            "│ " + " │ ".join("{:" + str(width) + "}" for width in col_widths) + " │"
        )

        def border_line(left, mid, right):
            pieces = ["─" * (width + 2) for width in col_widths]
            return left + mid.join(pieces) + right

        top_border = border_line("┌", "┬", "┐")
        header_sep = border_line("├", "┼", "┤")
        bottom_border = border_line("└", "┴", "┘")

        print(colored(top_border, color))
        print(colored(row_format.format(*table_data[0]), color))
        print(colored(header_sep, color))
        for row in table_data[1:]:
            print(colored(row_format.format(*row), color))
        print(colored(bottom_border, color))

    print_section(users_table, "blue")
    print_section(backups_table, "cyan")


# region ring_init
def ring_init() -> None:
    """
    Initializes the ring structure for a distributed system node.

    This function sets up the initial state of the node in the ring by
    defining the current node, its predecessor, and its successor.
    It also initializes an empty finger table.

    Global Variables:
    - predecessor: A dictionary representing the predecessor node.
    - successor: A dictionary representing the successor node.
    - current: A dictionary representing the current node, including its id, ip, and port.

    Note:
    - The `gs.my_node_id` and `gs.local_ip` are assumed to be globally accessible variables
      that provide the node's unique identifier and local IP address, respectively.
    - `SERVER_PORT` is assumed to be a globally defined constant representing the server port.
    """
    global predecessor, successor, current
    current = {"id": gs.my_node_id, "ip": gs.local_ip, "port": SERVER_PORT}
    predecessor = current
    successor = current
    finger_table = []


# region print_ft
def print_ft() -> None:
    """
    Prints the current state of the finger table and the predecessor-successor relationship.

    This function prints the IP addresses of the predecessor and successor nodes in the ring,
    followed by the contents of the finger table. The output is color-coded in yellow for better
    visibility.

    Returns:
        None
    """
    print(colored(f" {predecessor['ip']}  <<>>  {successor['ip']}", "yellow"))
    print_list(finger_table, "yellow")


# region sanity_check
def sanity_check() -> None:
    """
    Continuously prints the status of the connected nodes, predecessor, successor, and finger table every 15 seconds.

    This function runs an infinite loop that:
    - Prints the number of connected nodes.
    - Displays the IP addresses of the predecessor and successor nodes.
    - Prints the current state of the finger table.
    - Pauses for 15 seconds before repeating the process.

    Note:
        This function assumes that the variables `connected`, `predecessor`, `successor`, and `finger_table` are defined
        and accessible within the scope where this function is called.
    """
    while True:
        print(colored(f" NODES CONNECTED: {connected}", "green"))
        print(colored(f" {predecessor['ip']}  <<>>  {successor['ip']}", "green"))
        print_list(finger_table, "green")
        time.sleep(15)


# region hash
def hash(key: str) -> int:
    """
    Computes a simple polynomial hash of the string 'key' and reduces it modulo ID_SPACE.
    """
    h = 0
    for ch in key:
        h = (h * 31 + ord(ch)) % (2**M)
    return h


# region in_interval
def in_interval(val: int, start: int, end: int, inclusive_end: bool = False) -> bool:
    """
    Determines if 'val' is within the circular interval (start, end).
    If inclusive_end is True, the interval is (start, end].
    Assumes the identifier space (modulo ID_SPACE).
    """
    if start < end:
        return (start < val <= end) if inclusive_end else (start < val < end)
    else:
        return (
            (val > start or val <= end) if inclusive_end else (val > start or val < end)
        )


# region closest_preceding_finger
def closest_preceding_finger(id_val: int) -> dict:
    """
    Iterates over the finger table in reverse order and returns the node whose ID is
    the closest (preceding) to id_val, but greater than this node.
    If not found, returns the current node.
    """
    global finger_table
    for node in reversed(finger_table):
        if in_interval(node["id"], gs.my_node_id, id_val, inclusive_end=False):
            return node
    return current


# region is_alive
def is_alive(node: dict) -> bool:
    """
    Check if a node in the distributed system is alive by sending a ping message.

    Args:
        node (dict): A dictionary containing the IP address and port of the node.
                     Example: {"ip": "192.168.1.1", "port": 8080}

    Returns:
        bool: True if the node responds with a status of "alive", False otherwise.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.3)
            s.connect((node["ip"], node["port"]))
            msg = {"action": "ping"}
            s.sendall(json.dumps(msg).encode())
            resp = s.recv(4096)
            resp = json.loads(resp.decode())

            if resp["status"] == "alive":
                return True
            else:
                return False
    except Exception as e:
        return False


# region find_successor_hard
def find_successor_hard(id_val: int, event: int = -1) -> dict:
    """
    Find the successor node for a given id in a distributed system.

    This function searches through a list of connected nodes and returns the first node
    whose id is greater than the given id_val. If no such node is found, it returns the
    first node in the sorted list.

    Args:
        id_val (int): The id value for which to find the successor node.
        event (int, optional): An optional event identifier. Defaults to -1.

    Returns:
        dict: The successor node with an id greater than id_val, or the first node in the list if no such node exists.
    """
    list = nodes_connected_list(rint())

    # for i in list:
    #     VERBOSE and print(colored(i, "blue"))

    list.sort(key=lambda x: x["id"])

    for i in list:
        if i["id"] > id_val:
            return i
    return list[0]


# region find_successor
def find_successor(id_val: int, event: int = -1, hard_mode: int = 0) -> dict:
    """
    Find the successor node for a given identifier in a Chord ring.

    This function determines the successor node for a given identifier (id_val)
    in a distributed hash table (DHT) based on the Chord protocol. It can operate
    in a normal mode or a hard mode, and it can handle events to avoid redundant
    processing.

    Args:
        id_val (int): The identifier for which to find the successor node.
        event (int, optional): An event identifier to track and avoid redundant
                               processing. Defaults to -1.
        hard_mode (int, optional): A flag to indicate whether to use the hard mode
                                   for finding the successor. Defaults to 0.

    Returns:
        dict: A dictionary representing the successor node, or an empty dictionary
              if an error occurs or the event has already been processed.
    """
    if hard_mode:
        return find_successor_hard(id_val, event)
    if event != -1 and event in events:
        return {}
    events.add(event)

    global successor, predecessor

    if gs.my_node_id == successor["id"]:
        return current

    if in_interval(id_val, gs.my_node_id, successor["id"], inclusive_end=True):
        return successor
    else:
        next_node = closest_preceding_finger(id_val)
        if next_node["id"] == gs.my_node_id:
            return successor
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(TIMEOUT)
                s.connect((next_node["ip"], next_node["port"]))
                msg = {
                    "action": "find_successor",
                    "id": id_val,
                    "hard_mode": 0,
                    "event": event,
                }
                s.sendall(json.dumps(msg).encode())
                resp = s.recv(4096)
                if resp:
                    result = json.loads(resp.decode())
                    return result
        except Exception as e:
            log_message(
                colored(
                    f"[Chord] Error en find_successor RPC a nodo {next_node['id']}: {e}",
                    "red",
                )
            )
            return {}


# region find_predecessor_hard
def find_predecessor_hard(id_val: int, event: int = -1) -> dict:
    """
    Finds the predecessor node in a distributed system ring topology.

    This function searches through a list of connected nodes, sorted in descending order by their IDs,
    to find the node whose ID is less than the given id_val. If no such node is found, it returns the
    node with the highest ID.

    Args:
        id_val (int): The ID value for which the predecessor node is to be found.
        event (int, optional): An event identifier, default is -1. (Currently unused in the function)

    Returns:
        dict: A dictionary representing the predecessor node with keys "id" and "ip".
    """
    list = nodes_connected_list(rint())
    # for i in list:
    #     VERBOSE and print(colored(i, "magenta"))

    list.sort(key=lambda x: x["id"])
    list.reverse()

    for i in list:
        VERBOSE and print(colored(i["ip"], "cyan"))
    for i in list:
        if i["id"] < id_val:
            return i

    return list[0]


# region find_predecessor
def find_predecessor(id_val: int, event: int = -1, hard_mode: int = 0) -> dict:
    """
    Find the predecessor node for a given id in a Chord ring.

    This function determines the predecessor node for a given identifier (id_val) in a Chord distributed hash table.
    It can operate in two modes: normal and hard mode. In hard mode, it performs a more exhaustive search.

    Args:
        id_val (int): The identifier for which to find the predecessor.
        event (int, optional): An event identifier to avoid redundant processing. Defaults to -1.
        hard_mode (int, optional): Flag to indicate whether to use hard mode. Defaults to 0.

    Returns:
        dict: A dictionary representing the predecessor node. If no predecessor is found or an error occurs, an empty dictionary is returned.
    """
    if hard_mode:
        return find_predecessor_hard(id_val, event)

    if event != -1 and event in events:
        return {}
    events.add(event)

    global successor, predecessor

    if gs.my_node_id == successor["id"] or in_interval(
        id_val, gs.my_node_id, successor["id"], inclusive_end=True
    ):
        # Only one node or in the interval with the successor
        return current
    else:
        if hard_mode:
            for node in finger_table:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(TIMEOUT)
                        s.connect((node["ip"], node["port"]))
                        msg = {
                            "action": "find_predecessor",
                            "id": id_val,
                            "hard_mode": 1,
                            "event": event,
                        }
                        s.sendall(json.dumps(msg).encode())
                        resp = s.recv(4096)
                        if resp:
                            result = json.loads(resp.decode())
                            if len(result):
                                return result
                except Exception as e:
                    log_message(
                        colored(
                            f"[Chord] Error en find_predecessor RPC a nodo {node['id']}: {e}",
                            "red",
                        )
                    )
        else:
            next_node = closest_preceding_finger(id_val)
            if next_node["id"] == gs.my_node_id:
                return next_node
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(TIMEOUT)
                    s.connect((next_node["ip"], next_node["port"]))
                    msg = {
                        "action": "find_predecessor",
                        "id": id_val,
                        "hard_mode": 0,
                        "event": event,
                    }
                    s.sendall(json.dumps(msg).encode())
                    resp = s.recv(4096)
                    if resp:
                        result = json.loads(resp.decode())
                        return result
            except Exception as e:
                log_message(
                    colored(
                        f"[Chord] Error en find_predecessor RPC a nodo {next_node['id']}: {e}",
                        "red",
                    )
                )
                return {}


# region nodes_connected_list
def nodes_connected_list(event: int) -> list:
    """
    Retrieve a list of nodes connected in the Chord ring.

    This function attempts to gather a list of all nodes currently connected
    in the Chord ring by querying each node in the finger table. If the event
    is not -1 and is already present in the events set, an empty list is returned.
    Otherwise, the event is added to the events set, and the function proceeds
    to query each node in the finger table for their list of connected nodes.

    Args:
        event (int): An identifier for the event triggering this function call.

    Returns:
        list: A list of nodes currently connected in the Chord ring. Each node
              is represented as a dictionary containing node information.
    """
    if event != -1 and event in events:
        return []
    events.add(event)
    ret = [current]

    for node in finger_table:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(TIMEOUT)
                s.connect((node["ip"], node["port"]))
                msg = {"action": "nodes_connected_list", "event": event}
                s.sendall(json.dumps(msg).encode())
                resp = s.recv(4096)
                if resp:
                    result = json.loads(resp.decode())
                    ret.extend(result)
        except Exception as e:
            log_message(
                colored(
                    f"[Chord] Error buscando lista de nodos conectados en :{node['ip']}: {e}",
                    "red",
                )
            )
    return ret


# region nodes_connected()
def nodes_connected(event: int = -1) -> int:
    """
    Calculate the number of nodes connected in the network.

    This function attempts to connect to each node in the finger table and
    sends a request to determine the number of connected nodes. If an event
    is provided and it exists in the events set, the function returns 0.
    Otherwise, it adds the event to the events set and proceeds with the
    calculation.

    Args:
        event (int, optional): An identifier for the event. Defaults to -1.

    Returns:
        int: The total number of connected nodes.
    """
    if event != -1 and event in events:
        return 0
    events.add(event)

    ans = 1

    for node in finger_table:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(TIMEOUT)
                s.connect((node["ip"], node["port"]))
                msg = {"action": "nodes_connected", "event": event}
                s.sendall(json.dumps(msg).encode())
                resp = s.recv(4096)
                if resp:
                    result = json.loads(resp.decode())
                    ans += result["number"]
        except Exception as e:
            pass
            # log_message(colored(f"[Chord] Error calculando la cantidad de nodos conectados: {e} - {successor["ip"]}", "red"))
    return ans


# region update_successor
def update_successor(node: dict, new_successor: dict):
    """
    Updates the successor of a given node in a Chord distributed hash table.

    This function sends a message to the specified node to update its successor
    to the new successor node provided. It uses a TCP socket connection to
    communicate with the node.

    Args:
        node (dict): A dictionary containing the IP address and port of the node
                     to be updated. Example: {"ip": "127.0.0.1", "port": 5000}.
        new_successor (dict): A dictionary containing the IP address and port of
                              the new successor node. Example: {"ip": "127.0.0.1", "port": 5001}.

    Raises:
        Exception: If there is an error in connecting to the node or sending/receiving
                   the update message, an exception is caught and logged.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            s.connect((node["ip"], node["port"]))
            msg = {"action": "update_successor", "node": new_successor}
            s.sendall(json.dumps(msg).encode())
            resp = s.recv(4096)
    except Exception as e:
        log_message(colored(f"[Chord] Error updateando el sucesor: {e}", "red"))


# region update_predecessor
def update_predecessor(node: dict, new_predecessor: dict) -> None:
    """
    Updates the predecessor of a given node in a distributed system.

    This function sends a request to the specified node to update its predecessor
    to the new_predecessor node. It uses a socket connection to communicate with
    the node and sends a JSON message containing the action and the new predecessor
    information.

    Args:
        node (dict): A dictionary containing the IP address and port of the node to update.
            Example: {"ip": "127.0.0.1", "port": 5000}
        new_predecessor (dict): A dictionary containing the IP address and port of the new predecessor node.
            Example: {"ip": "127.0.0.1", "port": 5001}

    Raises:
        Exception: If there is an error while connecting to the node or sending the update request.

    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            s.connect((node["ip"], node["port"]))
            msg = {"action": "update_predecessor", "node": new_predecessor}
            s.sendall(json.dumps(msg).encode())
            resp = s.recv(4096)
    except Exception as e:
        log_message(colored(f"[Chord] Error updateando el predecesor: {e}", "red"))


# region update_ring
def update_ring() -> None:
    """
    Updates the ring topology by checking the number of connected nodes and updating the next node in the ring.

    This function performs the following steps:
    1. Updates the global variable `connected` with the number of currently connected nodes.
    2. Iterates through a range of values from 1 to M (exclusive).
    3. For each iteration, it checks if the number of connected nodes minus one is less than 2 raised to the power of the current iteration index.
    4. If the condition is met, the loop breaks.
    5. Otherwise, it generates a random integer event and calls the `update_next` function with the current iteration index and the event.

    Global Variables:
    - connected: An integer representing the number of connected nodes.

    Dependencies:
    - nodes_connected: A function that returns the number of connected nodes.
    - rint: A function that generates a random integer.
    - update_next: A function that updates the next node in the ring based on the given index and event.

    Note:
    - The value of M should be defined elsewhere in the code.
    """
    global connected
    connected = nodes_connected(rint())

    for i in range(1, M):
        if connected - 1 < 2**i:
            break
        event = rint()
        update_next(i, event)


# region update_next
def update_next(i: int, event: int) -> None:
    """
    Updates the next node in the Chord ring with the given event.

    This function attempts to propagate an event to the successor node in the Chord ring.
    If the event is already present in the events set, it returns an empty dictionary.
    Otherwise, it adds the event to the events set and sends an update message to the successor node.

    Args:
        i (int): The identifier of the current node.
        event (int): The event to be propagated.

    Returns:
        dict: An empty dictionary if the event is already present in the events set.

    Raises:
        Exception: If there is an error while updating the ring, an exception is logged.
    """
    if event != -1 and event in events:
        return {}
    events.add(event)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            s.connect((successor["ip"], successor["port"]))
            msg = {"action": "update", "i": i, "event": event}

            s.sendall(json.dumps(msg).encode())
            resp = s.recv(4096)

        update_finger_table(i, event)
    except Exception as e:
        log_message(colored(f"[Chord] Error updateando el anillo: {e}", "red"))


# region update_finger_table
def update_finger_table(i: int, event: int) -> None:
    """
    Updates the finger table entry at index `i` by querying the node specified in the previous entry.

    Raises:
        Exception: If there is an error during the socket connection or data transmission.

    Notes:
        - The function first checks if the current node has enough connections to update the finger table entry.
        - It then attempts to connect to the node specified in the previous finger table entry.
        - If the connection is successful, it sends a request to the node and updates the finger table with the response.
        - If the response indicates an invalid node (id == "-1"), the function returns without updating.
        - Any exceptions during the process are logged with an error message.
    """
    if connected - 1 < 2**i:
        return
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            s.connect((finger_table[i - 1]["ip"], finger_table[i - 1]["port"]))
            msg = {"action": "ask", "i": i - 1}
            s.sendall(json.dumps(msg).encode())
            resp = s.recv(4096)
            resp = json.loads(resp.decode())

            if resp["id"] == "-1":
                return

            if len(finger_table) == i:
                finger_table.append(resp)
            else:
                finger_table[i] = resp
    except Exception as e:
        log_message(colored(f"[Chord] Error updateando el finger_table: {e}", "red"))


# region join
def join(existing_node: dict) -> None:
    """
    Joins the current node to an existing Chord ring.

    This function attempts to join the current node to a Chord ring by connecting
    to an existing node in the ring. It updates the successor and predecessor of
    the current node and integrates the node into the ring. Additionally, it
    retrieves data from the successor node and updates the local database.

    Args:
        existing_node (dict): A dictionary containing the IP address and port of
                              an existing node in the Chord ring.

    Raises:
        Exception: If there is an error connecting to the existing node or
                   retrieving data from the successor node.

    Side Effects:
        - Updates the global variables `successor`, `predecessor`, and `update_ring_lock`.
        - Sends a join request to the existing node and processes the response.
        - Updates the local database with data retrieved from the successor node.
        - Calls `update_successor` and `update_predecessor` to update the ring structure.
        - Calls `full_replicate` to replicate data.
        - Calls `print_ft` to print the finger table.
    """
    global successor, predecessor, update_ring_lock
    update_ring_lock = True
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            s.connect((existing_node["ip"], existing_node["port"]))
            msg = {"action": "join", "id": gs.my_node_id}
            s.sendall(json.dumps(msg).encode())
            resp = s.recv(4096)
            if resp:
                resp = json.loads(resp.decode())
                succ = resp["successor"]
                pred = resp["predecessor"]
                successor = succ
                predecessor = pred
                update_successor(predecessor, current)
                update_predecessor(successor, current)

                VERBOSE and print(colored(resp, "magenta"))
                finger_table.append(successor)
                log_message(
                    colored(
                        f"[Chord] Nodo unido al anillo. Sucesor asignado: {successor['id']}",
                        "green",
                    )
                )
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(TIMEOUT)
                s.connect((successor["ip"], successor["port"]))
                msg = {"action": "to_predecessor"}
                s.sendall(json.dumps(msg).encode())
                resp = s.recv(4096)
                resp = json.loads(resp.decode())

                with gs.db_lock:
                    conn = sqlite3.connect(DB_FILE)
                    cursor = conn.cursor()
                    VERBOSE and print(
                        colored(f"INSERTING VALUES FROM SUCCESSOR\n{resp}", "magenta")
                    )
                    for value in resp:
                        if "node_id" not in value:
                            cursor.execute(
                                """
                                INSERT OR REPLACE INTO users (username, password, ip, public_key, last_update, status)
                                VALUES (?, ?, ?, ?, ?, ?)
                            """,
                                (
                                    value["username"],
                                    value["password"],
                                    value["ip"],
                                    value["public_key"],
                                    value["last_update"],
                                    value["status"],
                                ),
                            )
                        else:
                            cursor.execute(
                                """
                                INSERT OR REPLACE INTO backups (username, password, ip, public_key, last_update, status, node_id)
                                VALUES (?, ?, ?, ?, ?, ?, ?)
                            """,
                                (
                                    value["username"],
                                    value["password"],
                                    value["ip"],
                                    value["public_key"],
                                    value["last_update"],
                                    value["status"],
                                    value["node_id"],
                                ),
                            )
                    conn.commit()
                    conn.close()
                full_replicate()
                VERBOSE and print_db()
        except Exception as e:
            log_message(
                colored(f"[Chord] Error obteniendo datos desde el sucessor: {e}", "red")
            )

    except Exception as e:
        log_message(
            colored(
                f"[Chord] Error en join() con nodo existente: {e}. Se arranca como nodo inicial.",
                "red",
            )
        )
        predecessor = current
        successor = current
    update_ring_lock = False
    print_ft()


def stabilize():
    pass


# region chord_handler
def chord_handler(request: dict) -> dict:
    """
    Handles various actions related to the Chord protocol for a distributed hash table (DHT).

    Parameters:
    request (dict): A dictionary containing the action to be performed and any necessary parameters.

    Returns:
    dict: A dictionary containing the result of the action performed.

    Actions:
    - "join": Adds a new node to the ring.
        Parameters:
            - id (int): The ID of the node to join.
        Returns:
            - successor (dict): The successor node information.
            - predecessor (dict): The predecessor node information.

    - "find_successor": Finds the successor of a given node ID.
        Parameters:
            - id (int): The ID of the node.
            - event (int): Event identifier.
            - hard_mode (bool): Flag for hard mode.
        Returns:
            - dict: The successor node information.

    - "find_predecessor": Finds the predecessor of a given node ID.
        Parameters:
            - id (int): The ID of the node.
            - event (int): Event identifier.
            - hard_mode (bool): Flag for hard mode.
        Returns:
            - dict: The predecessor node information.

    - "update_successor": Updates the successor of the current node.
        Parameters:
            - node (dict): The new successor node information.
        Returns:
            - dict: An empty dictionary.

    - "update_predecessor": Updates the predecessor of the current node.
        Parameters:
            - node (dict): The new predecessor node information.
        Returns:
            - dict: An empty dictionary.

    - "ask": Retrieves the finger table entry at a given index.
        Parameters:
            - i (int): The index in the finger table.
        Returns:
            - dict: The finger table entry at index i or {"id": "-1"} if index is out of range.

    - "nodes_connected_list": Retrieves a list of connected nodes.
        Parameters:
            - event (int): Event identifier.
        Returns:
            - dict: A list of connected nodes.

    - "update": Updates the next node in the finger table.
        Parameters:
            - i (int): The index in the finger table.
            - event (int): Event identifier.
        Returns:
            - dict: An empty dictionary.

    - "nodes_connected": Retrieves the number of connected nodes.
        Parameters:
            - event (int): Event identifier.
        Returns:
            - dict: The number of connected nodes.

    - "inherit_predecessor": Inherits the predecessor node.
        Returns:
            - dict: An empty dictionary.

    - "to_predecessor": Transfers data to the predecessor node.
        Returns:
            - dict: The result of the transfer.

    - "hotfix_replicate": Performs a hotfix replication.
        Parameters:
            - i (int): The index for replication.
        Returns:
            - dict: An empty dictionary.

    - "replicate": Replicates data to other nodes.
        Parameters:
            - num (int): The number of replications.
            - data_list (list): The list of data to replicate.
        Returns:
            - dict: An empty dictionary.

    - "ping": Checks if the node is alive.
        Returns:
            - dict: {"status": "alive"}.

    - Any other action:
        Returns:
            - dict: {"status": "error", "message": "Acción desconocida en chord_handler: {action}"}.
    """
    global successor, predecessor, update_ring_lock
    action = request.get("action")

    if action == "join":
        id_val = request.get("id")
        print(colored(f"Joining node {id_val}", "green"))
        rs = find_successor(id_val, rint(), 1)
        rp = find_predecessor(id_val, rint(), 1)
        return {"successor": rs, "predecessor": rp}

    if action == "find_successor":
        id_val = request.get("id")
        event = request.get("event")
        hard_mode = request.get("hard_mode")
        result = find_successor(id_val, event, hard_mode)
        return result
    if action == "find_predecessor":
        id_val = request.get("id")
        event = request.get("event")
        hard_mode = request.get("hard_mode")
        result = find_predecessor(id_val, event, hard_mode)
        return result

    if action == "update_successor":
        successor = request.get("node")
        if len(finger_table):
            finger_table[0] = successor
        else:
            finger_table.append(successor)
        print_ft()
        return {}
    if action == "update_predecessor":
        predecessor = request.get("node")
        print_ft()
        return {}

    if action == "ask":
        i = request.get("i")
        if i > len(finger_table):
            return {"id": "-1"}
        return finger_table[i]

    if action == "nodes_connected_list":
        event = request.get("event")
        return nodes_connected_list(event)

    if action == "update":
        i = request.get("i")
        event = request.get("event")
        update_next(i, event)
        return {}

    if action == "nodes_connected":
        event = request.get("event")
        ans = nodes_connected(event)
        return {"number": ans}

    if action == "inherit_predecessor":
        inherit_predecessor()
        VERBOSE and print_db()
        return {}
    if action == "to_predecessor":
        ret = to_predecessor()
        VERBOSE and print(colored(f"TRANSFERING TO THE PREDECESSOR", "magenta"))
        return ret
    if action == "hotfix_replicate":
        i = request.get("i")
        VERBOSE and print(colored(f"HOT FIX REPLICATION: {i}", "magenta"))
        hotfix_replicate(i)
        return {}

    if action == "replicate":
        num = request.get("num")
        data_list = request.get("data_list")
        update_values(data_list)
        if num > 1:
            replicate(data_list, num - 1)
        VERBOSE and print_db()
        return {}

    elif action == "ping":
        return {"status": "alive"}
    else:
        return {
            "status": "error",
            "message": f"Acción desconocida en chord_handler: {action}",
        }


# region run_stabilize
def run_stabilize() -> None:
    """
    Continuously runs the stabilize function at regular intervals defined by RING_UPDATE_INTERVAL.

    This function enters an infinite loop where it calls the stabilize function and then sleeps
    for a duration specified by the RING_UPDATE_INTERVAL constant. It is used to maintain the
    stability of the ring in a distributed system.

    Note:
        This function will run indefinitely until the program is terminated.
    """
    while True:
        stabilize()
        time.sleep(RING_UPDATE_INTERVAL)


# region run_fix_fingers
def run_fix_fingers() -> None:
    """
    Periodically updates the finger table and the list of connected nodes in a distributed system.

    This function runs in an infinite loop, performing the following tasks:
    1. Checks if the `update_ring_lock` is set. If it is, the loop continues without making changes.
    2. Updates the list of connected nodes by calling `nodes_connected(rint())`.
    3. Calls `update_ring()` to update the ring structure.
    4. If the number of connected nodes has changed, it prints the new count of connected nodes.
    5. Adjusts the finger table by removing entries if the number of connected nodes is less than a threshold.
    6. Prints the updated finger table.
    7. Sleeps for a duration defined by `FIX_FINGERS_INTERVAL` before repeating the process.

    Global Variables:
    - connected: The current number of connected nodes.
    - update_ring_lock: A flag indicating whether the ring update process is locked.
    - finger_table: The finger table used for routing in the distributed system.
    - FIX_FINGERS_INTERVAL: The interval (in seconds) between successive updates.

    Note:
    - This function assumes the existence of several other functions and variables such as `nodes_connected()`, `rint()`, `update_ring()`, and `print_ft()`.
    """
    global connected
    while True:
        if update_ring_lock:
            continue

        oc = connected
        connected = nodes_connected(rint())

        update_ring()

        if oc != connected:
            print(colored(f" NODES CONNECTED: {connected}", "cyan"))
            while (
                not update_ring_lock
                and len(finger_table)
                and connected - 1 < 2 ** (len(finger_table) - 1)
            ):
                finger_table.pop(len(finger_table) - 1)
            print_ft()
        time.sleep(FIX_FINGERS_INTERVAL)


# region hotfix_replicate
def hotfix_replicate(i: int) -> None:
    """
    Perform a full replication and notify the predecessor node to replicate if needed.

    This function first calls `full_replicate()` to perform a complete replication.
    If the input parameter `i` is equal to 1, the function returns immediately.
    Otherwise, it attempts to notify the predecessor node to replicate by sending
    a message over a socket connection.

    Args:
        i (int): The number of times the replication notification should be propagated.

    Raises:
        Exception: If there is an error in connecting to the predecessor node or
                   sending/receiving the replication notification message.

    Note:
        The function logs an error message if it fails to notify the predecessor node.
    """
    full_replicate()
    if i == 1:
        return
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            s.connect((predecessor["ip"], predecessor["port"]))
            msg = {"action": "hotfix_replicate", "i": i - 1}
            s.sendall(json.dumps(msg).encode())
            resp = s.recv(4096)
    except Exception as e:
        log_message(
            colored(
                f"[Replication] Error notificando necesidad de replicacion  :{predecessor['ip']}: {e}",
                "red",
            )
        )


# region to_predecessor
def to_predecessor() -> list:
    """
    Transfers user data to the predecessor node in a distributed system.

    This function performs the following steps:
    1. Acquires a lock to ensure thread safety.
    2. Connects to the SQLite database and creates a custom hash function.
    3. Logs the action of sending data to the predecessor.
    4. Depending on the IDs of the current node and the predecessor, selects user data
       that needs to be transferred.
    5. Fetches the selected user data and converts it into a list of dictionaries.
    6. Fetches backup data from the backups table and appends it to the list of dictionaries.
    7. Deletes the transferred user data from the users table.
    8. Commits the changes and closes the database connection.

    Returns:
        list: A list of dictionaries containing user and backup data to be sent to the predecessor.
    """
    with gs.db_lock:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        conn.create_function("hash", 1, hash)
        log_message(colored("SENDING DATA TO PREDECESSOR", "magenta"))

        if predecessor["id"] < current["id"]:
            query = """
                SELECT username, password, ip, public_key, last_update, status
                FROM users
                WHERE hash(username) <= ? OR hash(username) > ?
            """
        else:
            query = """
                SELECT username, password, ip, public_key, last_update, status
                FROM users
                WHERE hash(username) <= ? AND hash(username) > ?
            """

        params = (predecessor["id"], current["id"])
        cursor.execute(query, params)
        new_data = cursor.fetchall()

        data_dict = []
        for data in new_data:
            data_dict.append(
                {
                    "username": data[0],
                    "password": data[1],
                    "ip": data[2],
                    "public_key": data[3],
                    "last_update": data[4],
                    "status": data[5],
                }
            )

        backup_query = """
            SELECT username, password, ip, public_key, last_update, status, node_id
            FROM backups
        """
        cursor.execute(backup_query)
        backups_data = cursor.fetchall()

        for data in backups_data:
            data_dict.append(
                {
                    "username": data[0],
                    "password": data[1],
                    "ip": data[2],
                    "public_key": data[3],
                    "last_update": data[4],
                    "status": data[5],
                    "node_id": data[6],
                }
            )

        delete_query = (
            """
            DELETE FROM users
            WHERE hash(username) <= ? OR hash(username) > ?
            """
            if predecessor["id"] < current["id"]
            else """
            DELETE FROM users
            WHERE hash(username) <= ? AND hash(username) > ?
            """
        )

        cursor.execute(delete_query, params)
        conn.commit()
        conn.close()

    return data_dict


# region inherit_predecessor
def inherit_predecessor() -> None:
    """
    Inherit data from the predecessor node and insert it into the current node's database.

    This function acquires a lock on the database, connects to it, and logs the action of inheriting
    predecessor data. Depending on the IDs of the predecessor and current nodes, it constructs an
    appropriate SQL query to select data from the `backups` table and insert it into the `users` table.
    The selected data is then fetched, transformed into a list of dictionaries, and replicated across
    a specified number of replicas.

    The function assumes the existence of global variables:
    - `gs.db_lock`: A threading lock for database operations.
    - `DB_FILE`: The path to the SQLite database file.
    - `predecessor`: A dictionary containing the predecessor node's information, including its ID.
    - `current`: A dictionary containing the current node's information, including its ID.
    - `NUM_OF_REPLICAS`: The number of replicas to create for the inherited data.

    The function performs the following steps:
    1. Acquires the database lock.
    2. Connects to the SQLite database.
    3. Logs the action of inheriting predecessor data.
    4. Constructs an SQL query based on the IDs of the predecessor and current nodes.
    5. Executes the query and fetches the resulting data.
    6. Transforms the fetched data into a list of dictionaries.
    7. Commits the transaction and closes the database connection.
    8. Replicates the transformed data across the specified number of replicas.

    Returns:
        None
    """
    with gs.db_lock:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        log_message(colored("INHERITING PREDECESSOR DATA", "magenta"))

        if predecessor["id"] < current["id"]:
            query = """
                INSERT INTO users (username, password, ip, public_key, last_update, status)
                SELECT username, password, ip, public_key, last_update, status
                FROM backups
                WHERE node_id > ? AND node_id <= ?
                RETURNING username, password, ip, public_key, last_update, status
            """
        else:
            query = """
                INSERT INTO users (username, password, ip, public_key, last_update, status)
                SELECT username, password, ip, public_key, last_update, status
                FROM backups
                WHERE node_id > ? OR node_id <= ?
                RETURNING username, password, ip, public_key, last_update, status
            """

        params = (predecessor["id"], current["id"])
        cursor.execute(query, params)
        new_data = cursor.fetchall()
        data_dict = []
        for data in new_data:
            data_dict.append(
                {
                    "username": data[0],
                    "password": data[1],
                    "ip": data[2],
                    "public_key": data[3],
                    "last_update": data[4],
                    "status": data[5],
                    "node_id": current["id"],
                }
            )
        conn.commit()
        conn.close()
    replicate(data_dict, NUM_OF_REPLICAS)


# region update_values
def update_values(data_list: list) -> None:
    """
    Updates the values in the database based on the provided data list.

    This function takes a list of dictionaries, where each dictionary contains
    user information. It updates the 'users' or 'backups' table in the database
    depending on whether the dictionary contains a 'node_id' key.

    Args:
        data_list (list): A list of dictionaries, where each dictionary contains
                          the following keys:
                          - username (str): The username of the user.
                          - password (str): The password of the user.
                          - ip (str): The IP address of the user.
                          - public_key (str): The public key of the user.
                          - last_update (str): The last update timestamp.
                          - status (str): The status of the user.
                          - node_id (str, optional): The node ID (only for backups).

    Returns:
        None
    """
    if not len(data_list):
        return

    with gs.db_lock:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        VERBOSE and print(colored("UPDATING VALUES", "magenta"))
        # VERBOSE and print(colored(data_list, "magenta"))

        for value in data_list:
            if "node_id" not in value:
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO users (username, password, ip, public_key, last_update, status)
                    VALUES (?, ?, ?, ?, ?, ?)
                """,
                    (
                        value["username"],
                        value["password"],
                        value["ip"],
                        value["public_key"],
                        value["last_update"],
                        value["status"],
                    ),
                )
            else:
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO backups (username, password, ip, public_key, last_update, status, node_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        value["username"],
                        value["password"],
                        value["ip"],
                        value["public_key"],
                        value["last_update"],
                        value["status"],
                        value["node_id"],
                    ),
                )

        conn.commit()
        conn.close()


# region full_replicate
def full_replicate() -> None:
    """
    Performs a full replication of user data from the database.

    This function retrieves all user data from the database, formats it into a list of dictionaries,
    and then calls the replicate function to handle the replication process. The function ensures
    thread safety by using a database lock.

    The user data includes the following fields:
    - username: The username of the user.
    - password: The password of the user.
    - ip: The IP address of the user.
    - public_key: The public key of the user.
    - last_update: The timestamp of the last update for the user.
    - status: The status of the user.

    The function also prints a message indicating that a full replication is being performed if
    the VERBOSE flag is set to True.
    VERBOSE and print(colored("DOING A FULL REPLICATION", "magenta"))
    """

    with gs.db_lock:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        query = """
            SELECT username, password, ip, public_key, last_update, status
            FROM users
        """
        cursor.execute(query)
        users_data = cursor.fetchall()
        conn.commit()
        conn.close()

    data_list = []
    for data in users_data:
        data_list.append(
            {
                "username": data[0],
                "password": data[1],
                "ip": data[2],
                "public_key": data[3],
                "last_update": data[4],
                "status": data[5],
            }
        )
    replicate(data_list)


# region replicate
def replicate(data_list: list, num: int = NUM_OF_REPLICAS) -> None:
    """
    Replicates the given data to the successor node in a distributed system.

    Parameters:
    data_list (list): A list of data dictionaries to be replicated. Each dictionary should contain the data to be replicated.
    num (int, optional): The number of replicas to create. Defaults to NUM_OF_REPLICAS.

    Returns:
    None

    Notes:
    - If the number of connected nodes is less than or equal to 1, or if the data_list is empty, or if num is less than or equal to 0, the function returns immediately without performing any replication.
    - The function ensures that the "node_id" key is present in each data dictionary. If not, it assigns the current node's ID to it.
    - The function attempts to connect to the successor node and send the replication request. If an error occurs during this process, it logs an error message.
    """
    if connected <= 1 or not len(data_list) or num <= 0:
        return
    num = min(num, connected - 1)
    # VERBOSE and print(colored(data_list, "red"))
    VERBOSE and print(f"REPLICATING {num}")
    if len(data_list) == 1:
        if "node_id" not in data_list[0]:
            data_list[0]["node_id"] = gs.my_node_id
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(TIMEOUT)
                s.connect((successor["ip"], successor["port"]))
                msg = {"action": "replicate", "num": num, "data_list": data_list}
                s.sendall(json.dumps(msg).encode())
                resp = s.recv(4096)
        except Exception as e:
            log_message(colored(f"[Chord] Error iniciando replicacion: {e}", "red"))
    else:
        for node in data_list:
            if "node_id" not in node:
                node["node_id"] = gs.my_node_id
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(TIMEOUT)
                s.connect((successor["ip"], successor["port"]))
                msg = {"action": "replicate", "num": num, "data_list": data_list}
                s.sendall(json.dumps(msg).encode())
                resp = s.recv(4096)
        except Exception as e:
            log_message(colored(f"[Chord] Error iniciando replicacion: {e}", "red"))


# region run_check_sccessor
def run_check_successor() -> None:
    """
    Periodically checks the status of the current successor node in the Chord ring.

    If the successor is found to be disconnected, it updates the ring by finding a new successor,
    updating the finger table, and notifying the new successor to inherit the predecessor's data.
    Additionally, it handles replication of data if there are multiple connected nodes.

    This function runs indefinitely in a loop with a sleep interval defined by CHECK_SUCCESSOR_INTERVAL.

    Global Variables:
    - CHECK_SUCCESSOR_INTERVAL: Interval time between each check.
    - successor: The current successor node.
    - update_ring_lock: A lock to prevent concurrent updates to the ring.

    Raises:
    - Exception: If there is an error while notifying the new successor to inherit data.
    """
    global CHECK_SUCCESSOR_INTERVAL, successor, update_ring_lock
    while True:
        time.sleep(CHECK_SUCCESSOR_INTERVAL)
        cnt = 0
        for i in range(3):
            if is_alive(successor):
                cnt += 1
        if cnt == 0:
            log_message(colored("[Chord] Successor disconnected", "red"))
            update_ring_lock = True

            successor = find_successor(current["id"] + 1, rint(), True)
            log_message(
                colored(f"[Chord] New successor found {successor['ip']}", "magenta")
            )

            if len(finger_table):
                finger_table[0] = successor
            else:
                finger_table.append(successor)
            update_predecessor(successor, current)
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(TIMEOUT)
                    s.connect((successor["ip"], successor["port"]))
                    msg = {"action": "inherit_predecessor"}
                    s.sendall(json.dumps(msg).encode())
                    resp = s.recv(4096)
            except Exception as e:
                log_message(
                    colored(
                        f"[Chord] Error mandando al nuevo sucesor a heredar datos del antiguo: {e}",
                        "red",
                    )
                )
            if connected > 1:
                hotfix_replicate(min(NUM_OF_REPLICAS, connected - 1))
            update_ring_lock = False
            print_db()


# region start_chord_maintenance
def start_chord_maintenance() -> None:
    """
    Launches the stabilization, fix_fingers, and check_predecessor functions in separate threads.
    """
    threading.Thread(target=run_stabilize, daemon=True).start()
    threading.Thread(target=run_fix_fingers, daemon=True).start()
    threading.Thread(target=run_check_successor, daemon=True).start()
    # threading.Thread(target=sanity_check, daemon=True).start()
    log_message(
        colored(
            "[Chord] Mantenimiento del anillo iniciado (stabilize, fix_fingers, check_predecessor).",
            "magenta",
        )
    )
