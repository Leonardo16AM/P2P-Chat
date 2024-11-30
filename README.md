# Distributed-Systems-Project


### To run:

On linux:

 >  chmod +x startup.sh
 > ./startup.sh

On windows:
 > ./startup.bat

To attach terminal:

 > docker exec -it client1 bash

To change ip:

 > docker network disconnect distributed-systems-project_server_network server
 > docker network connect --ip 192.168.1.3 distributed-systems-project_server_network server