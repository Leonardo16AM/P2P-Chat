
---

## Security

- **Password Security**: Passwords are hashed using `bcrypt`.  
- **Message Encryption**: RSA public-key encryption secures all messages.  
- **Data Integrity**: Ensured through consistent replication and encrypted transfers.

---

## Setup Instructions

### Prerequisites

- Docker  
- Python 3.x  
- Streamlit (for client GUI)  

### Running the Application

1. Clone the repository:
   ```bash
   git clone https://github.com/DanielMPMatCom/Distributed-Systems-Project.git
   cd Distributed-Systems-Project
   ```

2. Build and launch the Docker containers:

   **Linux:**
   ```bash
   chmod +x startup.sh
   ./startup.sh
   ```

   **Windows:**
   ```bash
   ./startup.bat
   ```

3. Start client or server GUIs as needed.

4. To change server IP:
   ```bash
   docker network disconnect distributed-systems-project_server_network server
   docker network connect --ip 192.168.1.3 distributed-systems-project_server_network server
   ```

---

## Additional Notes

- Logging in from a new client automatically transfers messages and disconnects the previous session.  
- The CHORD ring visualizer helps monitor server connections and data distribution.  
- Ensure all Docker containers are properly networked for seamless communication.
