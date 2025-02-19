import streamlit as st
import time
import json
import sys
import os
import threading
from getpass import getpass
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives import serialization
from termcolor import colored as col
import datetime


# Importar funciones adaptadas del módulo client.
# Se asume que en client.py se han definido las versiones adaptadas (para Streamlit) de:
# register, login, send_message_streamlit, query_user_info, show_chats, open_chat_streamlit,
# load_or_generate_keys, start_message_listener, start_pending_message_worker, etc.
from client.client import (
    register,
    login,
    send_message_streamlit,
    query_user_info,
    show_chats_streamlit,
    open_chat_streamlit,  # Idealmente, se modifica para que retorne los mensajes de un chat en vez de usar input()
    load_or_generate_keys,
    logout,
    start_message_listener_streamlit, 
    start_pending_message_worker, 
    send_alive_signal_streamlit,
    loguedout,
    stop_event,
    GESTOR_HOST,
    connect_to_server,
    discover_servers,
    is_server_active,
    GESTOR_PORT,

)

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
    st.session_state.chat_history = []  # Para mostrar el historial local (esto se podría actualizar dinámicamente)

# Definir el menú de navegación en la barra lateral
menu = st.sidebar.radio("Navigation", ["Login/Register", "Chat", "View Chats", "Open Chat", "Find User", "Project Report"])


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

# Página de Login/Register
if menu == "Login/Register":
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
                    "Servicios en segundo plano iniciados: escucha de mensajes, verificación de mensajes pendientes y envío de señal de vida. "
                    "Utiliza la barra lateral para navegar y cerrar sesión."
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
                # Aquí se podría actualizar el historial de chat (llamar a una función que recupere el historial)

                update_chat_history(st.session_state.username, target, message_content)
            else:
                st.warning("Please fill in both fields.")

# Página para ver todos los chats
elif menu == "View Chats":
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
elif menu == "Project Report":
    st.title("Project Report")
    st.subheader("Distributed System Design Report")
    try:
        with open("Distributed System Design.md", "r", encoding="utf-8") as f:
            report_md = f.read()
        st.markdown(report_md)
    except Exception as e:
        st.error("Could not load the project report.")

# Opción para cerrar sesión (por ejemplo, un botón en la barra lateral)
if st.sidebar.button("Logout"):
    st.session_state.logged_in = False
    st.session_state.username = ""
    st.session_state.chat_history = []
    logout()
    st.success("Logged out successfully!")

