import streamlit as st
import threading
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives import serialization
from termcolor import colored as col
import datetime

from client.client import (
    start_message_listener_streamlit, 
    start_pending_message_worker, 
    send_alive_signal_streamlit,
    send_message_streamlit,
    load_or_generate_keys,
    show_chats_streamlit,
    open_chat_streamlit,  
    connect_to_server,
    is_server_active,
    discover_servers,
    query_user_info,
    register,
    logout,
    login,
    another_session_start,
    stop_event,
    loguedout,
    GESTOR_HOST,
    GESTOR_PORT
)

if another_session_start:
    another_session_start = False
    st.session_state.logged_in = False
    st.session_state.username = ""
    st.session_state.chat_history = []
    st.success("Logged out successfully! Data transfered to the new session.")

def update_chat_history(sender, recipient, message):
                    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    new_entry = {"sender": sender, "recipient": recipient, "message": message, "timestamp": timestamp}
                    st.session_state.chat_history.append(new_entry)

# Inicializar variables de estado en la sesión
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "username" not in st.session_state:
    st.session_state.username = ""
if "public_key_str" not in st.session_state:
    # Cargar o generar las llaves RSA
    private_key, public_key = load_or_generate_keys()
    st.session_state.public_key_str = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    ).decode('utf-8')
if "chat_history" not in st.session_state:
    st.session_state.chat_history = []  

# Definir el menú de navegación en la barra lateral
menu = st.sidebar.radio("Navigation", ["Login/Register", "Chat", "View Chats", "Open Chat", "Find User", "Project README"])

if st.session_state.logged_in:
    st.sidebar.markdown(f"**Logged in as:** {st.session_state.username}")

threading.Thread(target=connect_to_server, daemon=True).start()

try:
    GESTOR_HOST = discover_servers()[0]
    print(col(f"FOUND SERVER ON:{GESTOR_HOST}", "green"))
except Exception as e:
    GESTOR_HOST = "192.168.1.2"

if is_server_active(GESTOR_HOST, GESTOR_PORT):
    print(col("El servidor está activo.", "green"))
else:
    SERVER_UP = False
    print(col("El servidor no está activo.", "red"))

private_key, public_key = load_or_generate_keys()
public_key_str = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
).decode()

if loguedout:
    loguedout = False

col1, col2 = st.columns([1, 4])
# Página de Login/Register
if menu == "Login/Register":

    with col1:
        st.image("wp2p.png", width=100)

    with col2:
        st.title("WhatsApp P2P - Login / Register")


    action = st.selectbox("Select Action", ["Register", "Login"])
    
    if action == "Login":
        username = st.text_input("Username", key="login_username")
        password = st.text_input("Password", type="password", key="login_password")
        if st.button("Login"):
            response = login(username, password)
            if response.get("status") == "success":
                st.session_state.logged_in = True
                st.session_state.username = username
                st.success("Login successful!")

                another_session_start = False
                
                # Iniciar los servicios en segundo plano sin bloquear la interfaz
                stop_event.clear()
                start_message_listener_streamlit(username)
                start_pending_message_worker(username)
                alive_thread = threading.Thread(
                    target=send_alive_signal_streamlit,
                    args=(username, st.session_state.public_key_str, stop_event),
                    daemon=True,
                )
                alive_thread.start()

                st.info(
                    "Background services started: message listening, pending message verification, and alive signal sending. "
                    "Use the sidebar to navigate and logout."
                )
            else:
                st.error(response.get("message"))
    else:  # Register
        reg_username = st.text_input("Choose a username", key="reg_username")
        reg_password = st.text_input("Choose a password", type="password", key="reg_password")
        reg_confirm = st.text_input("Confirm password", type="password", key="reg_confirm")
        if st.button("Register"):
            if reg_password != reg_confirm:
                st.error("Passwords do not match.")
            else:
                response = register(reg_username, reg_password, st.session_state.public_key_str)
                if response.get("status") == "success":
                    st.success("Registration successful! You can now log in.")
                else:
                    st.error(response.get("message"))

# Página para enviar mensajes (Chat)
elif menu == "Chat":

    with col1:
        st.image("wp2p.png", width=100)

    with col2:
        st.title("WhatsApp P2P - Chat")

    if not st.session_state.logged_in:
        st.warning("Please log in first!")
    else:
        st.markdown(f"**Logged in as:** {st.session_state.username}")
        target = st.text_input("Send message to (username)")
        message_content = st.text_area("Message", height=100)
        if st.button("Send"):
            if target and message_content:
                log_text = send_message_streamlit(st.session_state.username, target, message_content)
                print("log_text: ",log_text)
                st.success(log_text)

                update_chat_history(st.session_state.username, target, message_content)
            else:
                st.warning("Please fill in both fields.")

# Página para ver todos los chats
elif menu == "View Chats":

    with col1:
        st.image("wp2p.png", width=100)

    with col2:
        st.title("WhatsApp P2P - View Chats")
    
    if not st.session_state.logged_in:
        st.warning("Please log in first!")
    else:
        st.markdown(f"**Logged in as:** {st.session_state.username}")
        chats = show_chats_streamlit()
        if chats:
            for chat in chats:
                chat_id, user, last_msg, last_time = chat
                st.markdown(f"**Chat ID:** {chat_id} | **User:** {user} | **Last Message:** {last_msg} at {last_time}")
        else:
            st.info("No active chats.")

# Página para abrir un chat específico
elif menu == "Open Chat":
    with col1:
        st.image("wp2p.png", width=100)

    with col2:    
        st.title("WhatsApp P2P - Open Chat")
    
    if not st.session_state.logged_in:
        st.warning("Please log in first!")
    else:
        st.markdown(f"**Logged in as:** {st.session_state.username}")
        chat_id_input = st.text_input("Enter Chat ID to open", key="chat_id_input")
        if st.button("Open Chat"):
            try:
                chat_id = int(chat_id_input)
                messages = open_chat_streamlit(chat_id)  
                print("messahes: ", messages)
                if messages:
                    for sender, message, timestamp in messages:
                        if sender == st.session_state.username:
                            st.markdown(f"**You:** {message}  \n_{timestamp}_")
                        else:
                            st.markdown(f"**{sender}:** {message}  \n_{timestamp}_")
                else:
                    st.info("No messages in this chat.")
            except ValueError:
                st.error("Invalid Chat ID.")

# Página para buscar un usuario
elif menu == "Find User":
    with col1:
        st.image("wp2p.png", width=100)

    with col2:
        st.title("WhatsApp P2P - Find User")
        
    if not st.session_state.logged_in:
        st.warning("Please log in first!")
    else:
        target_username = st.text_input("Enter username to find", key="find_username")
        if st.button("Find"):
            if is_server_active(GESTOR_HOST, GESTOR_PORT):
                response = query_user_info(st.session_state.username, target_username)
                if response.get("status") == "success":
                    st.markdown(f"**User:** {target_username}")
                    st.markdown(f"**IP:** {response.get('ip')}")
                else:
                    st.error(response.get("message"))
            else:
                st.markdown("The server is not active. Please try again later.")

# Página del informe del proyecto
elif menu == "Project README":
    try:
        st.markdown("# WhatsApp P2P Project README")
        st.image("wp2p.png", width=400)
        with open("streamlit_report.md", "r", encoding="utf-8") as f:
            report_md = f.read()
        st.markdown(report_md, unsafe_allow_html=True)
        st.image("streamlit.png")
        with open("streamlit_report2.md", "r", encoding="utf-8") as f:
            report_md2 = f.read()
        st.markdown(report_md2, unsafe_allow_html=True)
        st.image("image.png")
        with open("streamlit_report3.md", "r", encoding="utf-8") as f:
            report_md3 = f.read()
        st.markdown(report_md2, unsafe_allow_html=True)


    except Exception as e:
        st.error("Could not load the project report.")

# Opción para cerrar sesión (por ejemplo, un botón en la barra lateral)
if st.sidebar.button("Logout"):
    logout()
    st.session_state.logged_in = False
    st.session_state.username = ""
    st.session_state.chat_history = []
    st.success("Logged out successfully!")