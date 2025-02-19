from flask import Flask, render_template, request, redirect, url_for, flash
import socket
import json
import random

app = Flask(__name__)
app.secret_key = "cambia_esta_clave_secreta"

# Tiempo de timeout para las conexiones en segundos
TIMEOUT = 5
# Base del puerto en el host donde están expuestos los nodos
BASE_PORT = 65440


def get_nodes(port: int) -> list:
    """
    Connects to the initial node (on the specified port) to obtain the list of nodes.
    """
    event = random.randint(1, int(1e9))
    msg = {"action": "nodes_connected_list", "event": event}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            s.connect(("localhost", port))
            s.sendall(json.dumps(msg).encode())
            resp = s.recv(4096)
            if resp:
                result = json.loads(resp.decode())
                return result
    except Exception as e:
        print(f"Error al conectar con localhost:{port} - {e}")
    return None


def get_node_info(port : int) -> dict:
    """
    Connects to the node (on the specified port) to obtain the node information.
    """
    event = random.randint(1, int(1e9))
    msg = {"action": "get_node_info", "event": event}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            s.connect(("localhost", port))
            s.sendall(json.dumps(msg).encode())
            resp = s.recv(4096)
            if resp:
                result = json.loads(resp.decode())
                return result
    except Exception as e:
        print(f"Error al obtener info de localhost:{port} - {e}")
    return {"error": "No se pudo obtener información"}


@app.route("/", methods=["GET", "POST"])
def index() -> str:
    """
    Handle the index route for the web application.
    """
    if request.method == "POST":
        try:
            port = int(request.form.get("port"))
        except ValueError:
            flash("Debe ingresar un puerto válido.", "danger")
            return redirect(url_for("index"))

        nodes = get_nodes(port)
        if nodes is None:
            flash("No se pudo obtener la lista de nodos.", "danger")
            return redirect(url_for("index"))

        nodes_info = []
        for node in nodes:
            try:
                if isinstance(node, dict):  # Extraer IP y puerto
                    node_ip = node["ip"]
                    node_port = BASE_PORT + int(
                        node_ip.split(".")[-1]
                    )  # 65440 + último octeto
                else:
                    continue  # Ignorar datos incorrectos

                info = get_node_info(node_port)
                nodes_info.append({"port": node_port, "info": info})
            except Exception as e:
                print(f"Error procesando nodo {node}: {e}")

        # Ordenar nodos por ID
        nodes_info.sort(key=lambda x: x["info"].get("id", float("inf")))

        return render_template("index.html", initial_port=port, nodes_info=nodes_info)
    return render_template("index.html", nodes_info=None)


@app.route("/refresh", methods=["POST"])
def refresh() -> str:
    """
    Route to refresh the information using the initial node's port.
    """
    try:
        port = int(request.form.get("port"))
    except ValueError:
        flash("No se proporcionó un puerto válido.", "danger")
        return redirect(url_for("index"))

    nodes = get_nodes(port)
    if nodes is None:
        flash("No se pudo obtener la lista de nodos.", "danger")
        return redirect(url_for("index"))

    nodes_info = []
    for node in nodes:
        try:
            if isinstance(node, dict):  # Extraer IP y puerto
                node_ip = node["ip"]
                node_port = BASE_PORT + int(node_ip.split(".")[-1])
            else:
                continue  # Ignorar datos incorrectos

            info = get_node_info(node_port)
            nodes_info.append({"port": node_port, "info": info})
        except Exception as e:
            print(f"Error procesando nodo {node}: {e}")

    nodes_info.sort(key=lambda x: x["info"].get("id", float("inf")))

    return render_template("index.html", initial_port=port, nodes_info=nodes_info)


if __name__ == "__main__":
    app.run(debug=True)
