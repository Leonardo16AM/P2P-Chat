
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

---

## Server Functionalities

1. **User & Connection Management**  
   - Manages user registration, authentication, and status updates.  
   - Tracks active users and their IPs across the network.  
   - Uses multicast for dynamic discovery of new servers.

2. **CHORD Ring & Data Replication**  
   - Implements CHORD ring architecture for efficient data distribution.  
   - Replicates user data to K successors for fault tolerance.  
   - Each server has two databases:  
     - `users`: Stores user credentials and metadata.  
     - `backups`: Contains replicated data from other nodes.

3. **Heartbeat Monitoring**  
   - Regular health checks to track online status.  
   - Automatically marks users as offline after inactivity.

4. **Server GUI (CHORD Visualizer)**  
   - Visualize the CHORD ring using:  
     ```bash
     python visualizer/app.py
     ```  
   - It will prompt for a port. Use the port from the server’s Docker container (check `docker-compose.yml`).  
