
**P2P-Chat** is a decentralized messaging platform that allows users to communicate directly without relying on central servers. It ensures privacy, security, and efficient message delivery using a peer-to-peer (P2P) architecture. The system integrates **local caching**, **SQLite databases** for user-specific storage, and **Docker-based networking** to simulate real distributed environments.

By implementing a **CHORD ring architecture**, P2P-Chat enables efficient data lookup, replication to K successors, and fault tolerance. If a node fails, its data remains accessible through replicated backups. **Multicast discovery** allows dynamic identification of servers within the network.

Developed in **Python** and containerized using **Docker**, the platform uses **RSA public-key cryptography** and **bcrypt** for secure authentication and message encryption. The system is designed for both academic exploration and real-world distributed applications.

---

## Features

### General

- **Decentralized Messaging**: Direct peer-to-peer messaging without central servers.
- **CHORD Ring Architecture**: Ensures data consistency, efficient lookups, and fault tolerance.
- **Data Replication**: Each server replicates data to K successors, maintaining availability.
- **Message Persistence**: Offline messages are cached and delivered when users reconnect.
- **Multicast Discovery**: Servers dynamically discover each other using multicast.
- **Secure Authentication**: User credentials are hashed with `bcrypt`, and RSA encryption secures communications.
- **Fault Tolerance**: Resilient messaging even during node or network failures.
- **Docker Integration**: Each client and server runs in isolated containers to mimic distributed networks.

---

## Client Functionalities

1. **User Registration & Login**  
   - Register with a unique username and password.  
   - Generates RSA key pairs for secure communication.  
   - Supports single-session logins — logging in from a new client disconnects the old session and transfers messages.

2. **Messaging**  
   - Direct messaging between users.  
   - Cached messages for offline recipients.  
   - Automatic delivery when recipients reconnect.  
   - Local storage of chat history using SQLite.

3. **Chat Management**  
   - View chat history, including delivered and pending messages.  
   - Check recipient status before sending messages.  
   - Seamless session transitions between devices.

4. **Client GUI**  
   - Run the client interface with:  
     ```bash
     docker exec -it client1 bash
     streamlit run app.py
     ```  
   - A simple interface for managing chats, sending messages, and viewing history.
  