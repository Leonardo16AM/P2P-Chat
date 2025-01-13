1- Arquitectura o el problema de como diseñar el sistema.
   Organización de su sistema distribuido
      - El sistema distribuido constara de los gestores
      - Cada uno conoce su sucesor, predecesor, y su finger table
      - Cada uno contiene el par <USUARIO (KEY), <IP,CONTRASENNIA,LAST_UPDATE> > para los datos que le tocan
   Roles de su sistema
      - Nodos clientes en la red de los clientes
      - Nodos gestores en la red de los servidores
         - Una cantidad N (puede ser 5) de gestores, seran especiales, ya que seran a partir de los cuales se pueden empezar a hacer querys los clientes, esta lista, lllaemosle "GESTORES INICIALES" se actualizara en todos los servidores de la red CHORD y se le enviara a cada cliente la version mas actualizada cada vez que haga una query.
2-Procesos o el problema de cuantos programas o servicios posee el sistema
   Todos los codigos correran en un mismo programa dentro de cada gestor, este posera varios hilos.
  
   En los cientes:
      - send_alive signal
      - recieve_msg
      - send_pending messages
   En los gestores:
      - Alive_signal reciever
      - Handle_client (responder peticiones)
      - Ring_update
      - Initial_gestors_update
      - Find_if_duplicates_are_alive
      - Recieve_duplicate

3-Comunicación o el problema de como enviar información mediante la red
   - Ahora mismo utilizamos sockets directamente pero pensamos que lo optimo para esta segunda etapa es utilizar ZeroMQ.
   Comunicacion:

   Cliente Servidor:
    - Para decir que esta vivo: PUB-SUB
    - Para preguntar el IP de otro usuario, REQ-REP

    SERVIDOR-SERVIDOR:
    - Para actualiazr la lista de GESTORES INCIALES es PUB-SUB
    - Para ver si los dublicados estan vivos es PUB-SUB
    - Para recibir datos para dublicar REQ-REP


4-Coordinación o el problema de poner todos los servicios de acuerdo

 Como cada recurso tiene una fecha, en el caso de haber duplicados o modificaciones se tomará el que tenga la fecha mas reciente. La decision de duplicarse la toma cada gestor y elige a quien duplicarse de manera random.


5-Nombrado y Localización o el problema de dónde se encuentra un recurso y como llegar al mismo

De la localización de recursos se encarga Chord. El nombrado será por nuestra key (USERNAME), donde se puede utilizar un hash polinomial. Los datos de cada gestor estarán almacenados en una database de SQLite

6-Consistencia y Replicación o el problema de solucionar los problemas que surgen a partir de tener varias copias de un mismo dato en el sistema.

Cada nodo estará duplicado en otros x nodos donde x es el mínimo entre la cantidad de nodos existentes y 3. Cada vez que se actualiza un dato se produce una replicación de este en los backups.
Como esto solo ocurre cuando un usuario cambia su IP o se desconecta, y eso no se espera que sea tan frecuente, dicha replicación no deberá sobrecargar los servidores.

7-Tolerancia a fallas o el problema de, para que pasar tanto trabajo distribuyendo datos y servicios si al fallar una componente del sistema todo se viene abajo.
   Respuesta a errores
    Como regularmente se verifica si las copias de cada gestor están "vivas", a menos que todas las copias fallen a la vez, la replicación es óptima. 

   Nivel de tolerancia a fallos esperado.
   
   Como se duplica la información de cada nodo en al menos otros 3 nodos (en caso de existir más de 3 nodos) el nivel de tolerancia a fallos es 2.

   Fallos parciales. Nodos caídos temporalmente. Nodos nuevos que se incorporan al sistema.
8-Seguridad o el problema de que tan vulnerable es su diseño
   seguridad con respecto a la comunicación
   seguridad con respecto al diseño
   Autorización y autenticación.
