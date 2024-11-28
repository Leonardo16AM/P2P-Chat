from client import initialize_database, save_message, get_chat_messages, list_chats, get_or_create_chat, review_pending_messages

# def setup_environment():
#     """Inicializa la base de datos y configura el entorno de prueba."""
#     print("Inicializando la base de datos...")
#     initialize_database()
#     print("Base de datos inicializada correctamente.")


if __name__ == "__main__":
    # Inicializar base de datos y crear chats
    initialize_database()
    chat_id1 = get_or_create_chat("user1")
    chat_id2 = get_or_create_chat("user2")

    # Guardar mensajes de prueba
    save_message(chat_id1, "user1", "Hola, ¿cómo estás?", delivered=False)
    save_message(chat_id2, "user2", "¿Vienes a la reunión?", delivered=False)

    # Revisar mensajes pendientes
    review_pending_messages()
