from client import initialize_database, save_message, get_chat_messages, list_chats, get_or_create_chat, review_pending_messages

def setup_environment():
    """Inicializa la base de datos y configura el entorno de prueba."""
    print("Inicializando la base de datos...")
    initialize_database()
    print("Base de datos inicializada correctamente.")

def simulate_users_and_chats():
    """Simula usuarios y crea algunos chats de prueba."""
    print("Creando usuarios y chats simulados...")
    chat1_id = get_or_create_chat("user1")
    chat2_id = get_or_create_chat("user2")
    chat3_id = get_or_create_chat("user3")
    print("Chats creados:")
    print(f"Chat 1 (ID: {chat1_id}) con user1")
    print(f"Chat 2 (ID: {chat2_id}) con user2")
    print(f"Chat 3 (ID: {chat3_id}) con user3")
    return chat1_id, chat2_id, chat3_id


def send_test_messages(chat1_id, chat2_id):
    """Envía mensajes simulados a los chats."""
    print("Enviando mensajes de prueba...")
    save_message(chat1_id, "me", "Hola, user1!", delivered=True)
    save_message(chat1_id, "user1", "Hola, ¿cómo estás?", delivered=True)
    save_message(chat2_id, "me", "Hola, user2!", delivered=False)  # No entregado
    print("Mensajes enviados correctamente.")



def list_all_chats():
    """Lista todos los chats activos."""
    print("\nListando chats activos:")
    chats = list_chats()
    for chat in chats:
        chat_id, username, last_message, last_timestamp = chat
        print(f"Chat ID: {chat_id}, Usuario: {username}, Último mensaje: '{last_message}' a las {last_timestamp}")


def view_chat_messages(chat_id):
    """Muestra los mensajes de un chat específico."""
    print(f"\nMostrando mensajes del chat ID: {chat_id}")
    messages = get_chat_messages(chat_id)
    if not messages:
        print("No hay mensajes en este chat.")
        return
    
    for sender, message, timestamp in messages:
        print(f"[{timestamp}] {sender}: {message}")





# if __name__ == "__main__":
#     # Inicializar base de datos y crear chats
#     initialize_database()
#     chat_id1 = get_or_create_chat("user1")
#     chat_id2 = get_or_create_chat("user2")

#     # Guardar mensajes de prueba
#     save_message(chat_id1, "user1", "Hola, ¿cómo estás?", delivered=False)
#     save_message(chat_id2, "user2", "¿Vienes a la reunión?", delivered=False)

#     # Revisar mensajes pendientes
#     review_pending_messages()


if __name__ == "__main__":
    # 1. Configurar el entorno
    setup_environment()
    
    # 2. Simular usuarios y chats
    chat1_id, chat2_id, chat3_id = simulate_users_and_chats()
    
    # 3. Enviar mensajes de prueba
    send_test_messages(chat1_id, chat2_id)
    
    # 4. Revisar chats y mensajes
    list_all_chats()
    view_chat_messages(chat1_id)
    view_chat_messages(chat2_id)
    view_chat_messages(chat3_id)
    
    print("\nValidación manual completada.")
