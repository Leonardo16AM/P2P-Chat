# gestor/ring.py
import socket
import time
import json
import random
from termcolor import colored
from .logging import log_message
from .config import SERVER_PORT, RING_UPDATE_INTERVAL, TIMEOUT,FIX_FINGERS_INTERVAL, CHECK_PREDECESSOR_INTERVAL,CHECK_SUCCESSOR_INTERVAL
import server.global_state as gs

finger_table=[]
predecessor=None
successor=None
current=None
connected=0
M=32
events=set()
update_ring_lock=False

#region rint
def rint():
    return random.randint(1,1000000000)

#region print_list
def print_list(lista, color):
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


#region ring_init
def  ring_init():
    global predecessor,successor,current 
    current={"id": gs.my_node_id, "ip": gs.local_ip, "port": SERVER_PORT}
    predecessor=current
    successor=current
    finger_table=[]

#region print_ft
def print_ft():
    print(colored(f" <<< : {predecessor['ip']}",'yellow'))
    print(colored(f" >>> : {successor['ip']}",'yellow'))
    print_list(finger_table,'yellow')

#region sanity_check
def sanity_check():
    while True:
        print(colored(f" NUMBER OF NODES: {connected}",'green'))
        print(colored(f" <<< : {predecessor['ip']}",'green'))
        print(colored(f" >>> : {successor['ip']}",'green'))
        print_list(finger_table,'green')
        time.sleep(15)

#region hash
def hash(key: str) -> int:
    """
    Calcula un hash polinomial simple de la cadena 'key' y lo reduce módulo ID_SPACE.
    """
    h = 0
    for ch in key:
        h = (h * 31 + ord(ch)) % (2**M)
    return h

#region in_interval
def in_interval(val: int, start: int, end: int, inclusive_end: bool = False) -> bool:
    """
    Determina si 'val' se encuentra en el intervalo circular (start, end).
    Si inclusive_end es True, el intervalo es (start, end].
    Se asume el espacio de identificadores (módulo ID_SPACE).
    """
    if start < end:
        return (start < val <= end) if inclusive_end else (start < val < end)
    else:
        return (val > start or val <= end) if inclusive_end else (val > start or val < end)


#region closest_preceding_finger
def closest_preceding_finger(id_val: int) -> dict:
    """
    Recorre la finger table en orden inverso y retorna el nodo cuya ID sea
    el más cercano (precedente) a id_val, pero mayor que este nodo.
    Si no se encuentra, retorna el propio nodo.
    """
    global finger_table
    for entry in reversed(finger_table):
        node = entry["node"]
        if in_interval(node["id"], gs.my_node_id, id_val, inclusive_end=False):
            return node
    return current

def is_alive(node):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.3)
            s.connect((node["ip"], node["port"]))
            msg = {"action": "ping"}
            s.sendall(json.dumps(msg).encode())
            resp = s.recv(4096)
            resp=json.loads(resp.decode())
            
            if resp['status']=="alive":
                return True   
            else:
                return False
    except Exception as e:
        return False

#region find_successor_hard
def find_successor_hard(id_val,event=-1):
    list=nodes_connected_list(rint())

    for i in list:
        print(colored(i,'blue'))

    list.sort(key=lambda x:x['id'])

    for i in list:
        if i['id']>id_val:
            return i
    return list[0]
    
#region find_successor
def find_successor(id_val,event=-1,hard_mode=0):
    if hard_mode:
        return find_successor_hard(id_val,event)
    if event!=-1 and event in events:
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
                msg = {"action": "find_successor", "id": id_val,"hard_mode":0,"event":event}
                s.sendall(json.dumps(msg).encode())
                resp = s.recv(4096)
                if resp:
                    result = json.loads(resp.decode())
                    return result
        except Exception as e:
            log_message(colored(f"[Chord] Error en find_successor RPC a nodo {next_node['id']}: {e}", "red"))
            return {}

#region find_predecessor_hard
def find_predecessor_hard(id_val,event=-1):
    list=nodes_connected_list(rint())
    for i in list:
        print(colored(i,'magenta'))

    list.sort(key=lambda x:x['id'])
    list.reverse()

    for i in list:
        print(colored(i['ip'],'cyan'))
    for i in list:
        if i['id']<id_val:
            return i
        
    return list[0]

#region find_predecessor
def find_predecessor(id_val,event=-1,hard_mode=0):
    if hard_mode:
        return find_predecessor_hard(id_val,event)
    
    if event!=-1 and event in events:
       return {}
    events.add(event)
    
    global successor, predecessor

    if gs.my_node_id == successor["id"] or in_interval(id_val, gs.my_node_id, successor["id"], inclusive_end=True):
        # Only one node or in the interval with the successor
        return current
    else:
        if hard_mode:
            for node in finger_table:
                try:    
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(TIMEOUT)
                        s.connect((node["ip"], node["port"]))
                        msg = {"action": "find_predecessor", "id": id_val,"hard_mode":1,"event":event}
                        s.sendall(json.dumps(msg).encode())
                        resp = s.recv(4096)
                        if resp:
                            result = json.loads(resp.decode())
                            if len(result):
                                return result
                except Exception as e:
                    log_message(colored(f"[Chord] Error en find_predecessor RPC a nodo {node['id']}: {e}", "red"))
        else:
            next_node = closest_preceding_finger(id_val)
            if next_node["id"] == gs.my_node_id:
                return next_node
            try:    
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(TIMEOUT)
                    s.connect((next_node["ip"], next_node["port"]))
                    msg = {"action": "find_predecessor", "id": id_val,"hard_mode":0,"event":event}
                    s.sendall(json.dumps(msg).encode())
                    resp = s.recv(4096)
                    if resp:
                        result = json.loads(resp.decode())
                        return result
            except Exception as e:
                log_message(colored(f"[Chord] Error en find_predecessor RPC a nodo {next_node['id']}: {e}", "red"))
                return {}

#region nodes_connected_list
def nodes_connected_list(event):
    if event!=-1 and event in events:
       return []
    events.add(event)
    ret=[current]

    for node in finger_table:
        try:    
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(TIMEOUT)
                s.connect((node["ip"], node["port"]))
                msg = {"action": "nodes_connected_list", "event":event}
                s.sendall(json.dumps(msg).encode())
                resp = s.recv(4096)
                if resp:
                    result = json.loads(resp.decode())
                    ret.extend(result)
        except Exception as e:
            log_message(colored(f"[Chord] Error buscando lista de nodos conectados en :{node['ip']}: {e}", "red"))
    return ret

#region nodes_connected()
def nodes_connected(event=-1):
    if event!=-1 and event in events:
       return 0
    events.add(event)
    
    ans=1
    try:    
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            s.connect((successor["ip"], successor["port"]))
            msg = {"action": "nodes_connected","event":event}
            s.sendall(json.dumps(msg).encode())
            resp = s.recv(4096)
            if resp:
                result = json.loads(resp.decode())
                ans+=result['number']
    except Exception as e:
        log_message(colored(f"[Chord] Error calculando la cantidad de nodos conectados: {e} - {successor["ip"]}", "red"))
    return ans

#region update_successor
def update_successor(node,new_successor):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            s.connect((node["ip"], node["port"]))
            msg = {"action": "update_successor", "node": new_successor}
            s.sendall(json.dumps(msg).encode())
            resp = s.recv(4096)
    except Exception as e:
        log_message(colored(f"[Chord] Error updateando el sucesor: {e}", "red"))


#region update_predecessor
def update_predecessor(node,new_predecessor):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            s.connect((node["ip"], node["port"]))
            msg = {"action": "update_predecessor", "node":new_predecessor}
            s.sendall(json.dumps(msg).encode())
            resp = s.recv(4096)
    except Exception as e:
        log_message(colored(f"[Chord] Error updateando el predecesor: {e}", "red"))



#region update_ring
def update_ring():
    global connected
    connected=nodes_connected(rint())
  
    for i in range(1,M):
        if connected-1<2**i:
            break    
        event=rint()
        update_next(i,event)


#region update_next
def update_next(i,event):
    if event!=-1 and event in events:
       return {}
    events.add(event)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            s.connect((successor["ip"], successor["port"]))
            msg = {"action": "update", "i": i,"event":event}
            
            s.sendall(json.dumps(msg).encode())
            resp = s.recv(4096)
            
        update_finger_table(i,event)
    except Exception as e:
        log_message(colored(f"[Chord] Error updateando el anillo: {e}", "red"))


#region update_finger_table
def update_finger_table(i,event):
    if connected-1<2**i:
        return    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            s.connect((finger_table[i-1]["ip"], finger_table[i-1]["port"]))
            msg = {"action": "ask", "i": i-1}
            s.sendall(json.dumps(msg).encode())
            resp = s.recv(4096)
            resp=json.loads(resp.decode())
            
            if resp['id']=="-1":
                return      
            
            if len(finger_table)==i:
                finger_table.append(resp)
            else:
                finger_table[i]=resp
    except Exception as e:
        log_message(colored(f"[Chord] Error updateando el finger_table: {e}", "red"))
        


#region join
def join(existing_node: dict):
    global successor,predecessor,update_ring_lock
    update_ring_lock=True
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            s.connect((existing_node["ip"], existing_node["port"]))
            msg = {"action": "join", "id": gs.my_node_id}
            s.sendall(json.dumps(msg).encode())
            resp = s.recv(4096)
            if resp:
                resp = json.loads(resp.decode())
                succ=resp['successor']
                pred=resp['predecessor']
                successor = succ
                predecessor = pred
                update_successor(predecessor,current)
                update_predecessor(successor,current)

                print(colored(resp,'magenta'))
                finger_table.append(successor)
                log_message(colored(f"[Chord] Nodo unido al anillo. Sucesor asignado: {successor['id']}", "green"))

    except Exception as e:
        log_message(colored(f"[Chord] Error en join() con nodo existente: {e}. Se arranca como nodo inicial.", "red"))
        predecessor = current
        successor = current
    update_ring_lock=False
    print_ft()


def fix_fingers():
    pass

def stabilize():    
    pass

def check_predecessor():
    pass

    

#region chord_handler
def chord_handler(request: dict) -> dict:
    global successor,predecessor,update_ring_lock
    action = request.get("action")

    if action == "join":
        id_val = request.get("id")
        print(colored(f"Joining node {id_val}",'green'))
        rs = find_successor(id_val,rint(),1)
        rp = find_predecessor(id_val,rint(),1)
        return {"successor":rs,"predecessor":rp}
    
    if action == "find_successor":
        id_val = request.get("id")
        event = request.get("event")
        hard_mode =  request.get("hard_mode")
        result = find_successor(id_val,event,hard_mode)
        return result
    if action == "find_predecessor":
        id_val = request.get("id")
        event = request.get("event")
        hard_mode =  request.get("hard_mode")
        result = find_predecessor(id_val,event,hard_mode)
        return result
    
    if action=="update_successor":
        successor=request.get("node")
        if len(finger_table):
            finger_table[0]=successor
        else: 
            finger_table.append(successor)
        print_ft()
        return {}
    if action=="update_predecessor":
        predecessor=request.get("node")
        print_ft()
        return {}
    
    if action == "ask":
        i=request.get('i')
        if(i>len(finger_table)):
            return {'id':"-1"}
        return finger_table[i]
    
    
    if action == "nodes_connected_list":
        event=request.get('event')
        return nodes_connected_list(event)
    
    
    if action =='update':
        i=request.get('i')
        event=request.get('event')
        update_next(i,event)
        return {}
    
    if action =='nodes_connected':
        event=request.get('event')
        import threading
        ans=nodes_connected(event)
        return {"number":ans}

    elif action == "ping":
        return {"status": "alive"}
    else:
        return {"status": "error", "message": f"Acción desconocida en chord_handler: {action}"}


#region run_stabilize
def run_stabilize():
    while True:
        stabilize()
        time.sleep(RING_UPDATE_INTERVAL)

#region run_fix_fingers
def run_fix_fingers():
    global connected
    while True:
        if update_ring_lock:
            continue
        
        oc=connected
        connected=nodes_connected(rint())
        
        update_ring()

        if oc!=connected:
            print(colored(f"NODES CONNECTED: {connected}",'cyan'))
            while  not update_ring_lock and len(finger_table) and connected-1<2**(len(finger_table)-1): 
                finger_table.pop(len(finger_table)-1)
            print_ft()
        time.sleep(FIX_FINGERS_INTERVAL)

#region run_check_sccessor
def run_check_successor():
    global CHECK_SUCCESSOR_INTERVAL, successor,update_ring_lock
    while True:
        time.sleep(CHECK_SUCCESSOR_INTERVAL)
        cnt=0
        for i in range(3):
            if(is_alive(successor)):
                cnt+=1
        if cnt==0:
            log_message(colored("[Chord] Successor disconnected",'red'))
            update_ring_lock=True

            successor=find_successor(current['id']+1,rint(),True)
            log_message(colored(f"[Chord] New successor found {successor['ip']}",'magenta'))
            
            if CHECK_SUCCESSOR_INTERVAL==5:
                CHECK_SUCCESSOR_INTERVAL=2
            if len(finger_table):
                finger_table[0]=successor
            else: 
                finger_table.append(successor)
            update_predecessor(successor,current)
            update_ring_lock=False

#region run_check_predecessor
def run_check_predecessor():
    while True:
        check_predecessor()
        time.sleep(CHECK_PREDECESSOR_INTERVAL)

#region start_chord_maintenance
def start_chord_maintenance():
    """
    Lanza en hilos separados las funciones de estabilización, fix_fingers y check_predecessor.
    """
    import threading
    threading.Thread(target=run_stabilize, daemon=True).start()
    threading.Thread(target=run_fix_fingers, daemon=True).start()
    threading.Thread(target=run_check_predecessor, daemon=True).start()
    threading.Thread(target=run_check_successor, daemon=True).start()
    threading.Thread(target=sanity_check, daemon=True).start()
    log_message(colored("[Chord] Mantenimiento del anillo iniciado (stabilize, fix_fingers, check_predecessor).", "magenta"))
