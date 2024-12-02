# Distributed-Systems-Project. **WhatsApp P2P**

## Overview

This project is a decentralized Peer-to-Peer (P2P) messaging application inspired by the functionalities of modern chat systems like WhatsApp. The application enables users to communicate securely and efficiently without relying on a centralized server to store messages. Instead, the architecture leverages local caching, SQLite databases for user-specific storage, and Docker-based networking to simulate real-world distributed systems.

The project is built in Python and employs Docker for containerization, with multiple interconnected networks to simulate distributed behavior. It incorporates public-key cryptography (RSA) for user authentication and message security, ensuring privacy and integrity.

---

## Features

### General Features
- **Decentralized Messaging**: Messages are exchanged directly between users without a central server.
- **Message Persistence**: Messages sent to offline users are cached locally and delivered when they come online.
- **User Authentication**: Secure registration and login mechanisms using hashed passwords (via `bcrypt`) and RSA public/private key pairs.
- **Distributed Fault Tolerance**: Mechanisms to handle network disconnections and cache user information for seamless recovery.
- **Docker Integration**: Users are simulated in separate Docker containers, communicating over a virtual network.

### Client Functionalities
1. **User Registration**:
   - A user can register with a unique username and password.
   - The client generates RSA key pairs for the user and securely stores them locally.

2. **Login and Authentication**:
   - Users log in with their credentials.
   - Successful login initializes the local database and starts background processes for message listening and delivery.

3. **Message Sending**:
   - Direct message exchange with online users.
   - If the recipient is offline, the message is cached in the sender’s database and delivered upon reconnection.

4. **Message Receiving**:
   - A listening service runs in each client, receiving messages sent from other users.
   - Messages are saved locally and displayed in real time.

5. **Pending Message Delivery**:
   - When a recipient comes online, pending messages are automatically sent by the sender’s client.

6. **Chat Management**:
   - Users can view their chat history, including delivered and pending messages.

7. **Network Resilience**:
   - Cached IPs are used to send messages directly to known users even during network outages.
   - The system verifies the online status of recipients before message delivery.

8. **Database Persistence**:
   - SQLite is used for storing user data, chat history, and pending messages, ensuring consistency across sessions.

### Manager (Gestor) Functionalities
1. **User Management**:
   - Handles user registration, authentication, and status updates.
   - Maintains a central SQLite database (`chat_manager.db`) for user credentials, public keys, and connection metadata.

2. **IP Resolution and Notification**:
   - Tracks online status and IP addresses of users.
   - Notifies clients when users connect or disconnect.

3. **Heartbeat Monitoring**:
   - Periodic "alive signals" from clients to ensure accurate user status.
   - Automatically marks users as disconnected after a timeout.

4. **User Lookup**:
   - Responds to client queries about other users' connection status and public keys.

5. **Logging and Debugging**:
   - Logs all key events, such as registrations, logins, and errors, for debugging and monitoring purposes.

---

## Technical Details

### Architecture
- **Client**: Each client is a Docker container running a Python script (`client.py`) that manages the user interface, message handling, and database operations.
- **Manager (Gestor)**: A central service running in its own Docker container. It handles user registration, login, and IP management.
- **Networking**: Clients and the manager communicate over Docker networks. A virtual router connects subnets to simulate distributed environments.

### Database
#### Client-Side
- **SQLite Tables**:
  - `chats`: Tracks all active chats.
  - `messages`: Stores sent and received messages.
  - `pending_messages`: Keeps messages destined for offline users.

#### Manager-Side
- **SQLite Tables**:
  - `users`: Stores user credentials, public keys, and connection metadata.

### Security
- **Authentication**:
  - Passwords are hashed using `bcrypt`.
  - RSA keys are used for secure message exchanges and user identification.
- **Data Integrity**:
  - All messages are sent over TCP sockets with checks for recipient status.

---

## Setup Instructions

### Running the Application
1. Clone the repository:
   ```bash
   git clone https://github.com/DanielMPMatCom/Distributed-Systems-Project.git
   cd Distributed-Systems-Project
   ```

2. Build and launch the Docker containers:

On linux:

	```bash
	chmod +x startup.sh
	./startup.sh
	```

On windows:
	```bash
	./startup.bat
	```

3. Interact with the clients:
   - Attach to a client container in:
     ```bash
     docker exec -it client1 bash
     python3 client.py
     ```

4. To change ip:

 	```bash
 	docker network disconnect distributed-systems-project_server_network server
	docker network connect --ip 192.168.1.3 distributed-systems-project_server_network server
	```

### Prerequisites
- Docker




