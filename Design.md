# Diseño del Sistema Distribuido

## 1. Arquitectura o el problema de como diseñar el sistema

El sistema utilizará una arquitectura peer to peer basada en Chord para estructurar la red de nodos. Para este proyecto, su diseño de anillo distribuido y el uso de claves hash para asignar y localizar recursos son ideales para garantizar que las direcciones de usuarios, claves públicas y mensajes pendientes puedan encontrarse eficientemente (O(log N)), incluso en redes dinámicas donde los nodos pueden unirse o abandonar la red en cualquier momento. Chord también proporciona una solución resiliente y descentralizada, lo que elimina puntos únicos de fallo, al tiempo que mantiene la simplicidad de diseño necesaria para la implementación del sistema distribuido.

Cada cliente representa un nodo en el anillo, identificado por un ID único generado a partir de un hash de su clave pública.

### Organización del sistema distribuido

La red se organiza en un anillo virtual en el que cada nodo conoce:

1. **Su sucesor**: El nodo inmediatamente siguiente en el anillo.
2. **Su predecesor**: El nodo inmediatamente anterior en el anillo.
3. **Finger Table**: Una tabla que optimiza las búsquedas al apuntar a nodos específicos a intervalos calculados de manera logarítmica.

Los datos se distribuyen en el anillo según una función hash que mapea claves (como nombres de usuario o mensajes) a nodos responsables de esos datos.

### Roles del sistema

- **Nodo cliente**:

  - Se conecta al anillo como un nodo Chord.
  - Almacena mensajes pendientes y direcciones IP de otros usuarios en el anillo.
  - Responde a solicitudes de búsqueda y almacenamiento en el anillo.
  - Envía mensajes directamente a otros nodos o almacena los mensajes en el nodo responsable cuando el destinatario está desconectado.
- **Bootstrap Node**:

  - Sirve como punto de entrada inicial para los nodos nuevos.
  - No participa activamente en la DHT ni almacena datos, pero permite localizar el primer nodo para unirse al anillo.

### Distribución de servicios en ambas redes de docker

**1. Red de clientes**

- Los clientes formarán el anillo Chord y estarán conectados a una red Docker dedicada.
- Cada nodo cliente ejecutará:
  - Un proceso para almacenar y buscar claves en la DHT.
  - Un servidor para aceptar mensajes de otros nodos.
  - Una base de datos SQLite para almacenar mensajes enviados, recibidos y pendientes.
  - Una implementación de la Finger Table para optimizar las búsquedas.

**2. Red del servidor**

- El nodo bootstrap se ejecutará en una red separada y estará conectado a través de un router Docker.
- Proporcionará el primer punto de contacto para nodos nuevos que desean unirse al anillo.

**3. Conexión a través de un router**

- Un router Docker conecta las dos redes (clientes y servidor), lo que permitirá que los nodos de ambas redes se comuniquen.

## 2. Procesos o el problema de cuantos programas o servicios posee el sistema

El sistema consta de los siguientes servicios principales:

  1. **Nodo cliente**: Cada cliente representa un nodo dentro del anillo Chord, gestionando sus propios mensajes y participando en la DHT.
  2. **Nodo bootstrap**: Funciona como punto de entrada para nuevos nodos que desean unirse al anillo.
  3. **Router (en Docker)**: Interconecta las redes de clientes y del servidor para facilitar la comunicación.

### Tipos de procesos dentro del sistema

1. **Nodo cliente**:
  - **Proceso principal**: Gestiona la interacción del usuario y la lógica del nodo en Chord.
  - **Subprocesos**:
    - Listener Thread: Recibe mensajes entrantes.
    - Heartbeat Thread: Envía señales periódicas al sistema para mantener el nodo activo.
    - Message Delivery Thread: Maneja la entrega de mensajes pendientes.
    - Finger Table Maintenance Thread: Actualiza las tablas de dedos en el anillo.

2. **Nodo bootstrap**:
  - Proceso único que gestiona las solicitudes de entrada al anillo.

3. **Router**:
  - Proceso único para gestionar el tráfico entre las redes Docker.

### Organización o agrupación de los procesos según su arquitectura

- **Nodo cliente**: Ejecuta su proceso principal y subprocesos en una única instancia por cada usuario. Cada cliente se conecta al anillo a través del bootstrap al inicializarse.
- **Nodo bootstrap**: Proceso único centralizado para manejar la entrada al anillo.
- **Router**: Proceso aislado encargado de comunicar redes Docker.

### Tipo de patrón de diseño con respecto al desempeño

- **Modelo multithreaded**: Utilizado en los nodos clientes para manejar tareas concurrentes como recepción de mensajes, envío de mensajes pendientes y mantenimiento de Finger Tables, maximizando la eficiencia en operaciones basadas en I/O.
- **Modelo asincrónico**: Se emplea en operaciones ligeras no críticas, como solicitudes al bootstrap y actualizaciones de tablas.
- **Procesos únicos**: Tanto el bootstrap como el router funcionan como procesos únicos dado su rol centralizado y específico en el sistema.

## 3. Comunicación o el problema de cómo se comunican los procesos

ZeroMQ ofrece un modelo eficiente para comunicación distribuida, tolerante a fallos y fácil de integrar en arquitecturas como Chord. Su capacidad para gestionar diferentes patrones de mensajes permite implementar tanto la inicialización de nodos como la resolución de claves y la propagación de eventos de manera escalable. Además, al combinarlo con almacenamiento persistente, el sistema asegura la entrega eventual de mensajes.

### Tipo de comunicación

El sistema empleará un enfoque basado en **sockets asincrónicos** implementados mediante **ZeroMQ (ZMQ)**, con los siguientes patrones:
- **REQ-REP (Solicitud-Respuesta):** Para consultas específicas, como resolver el sucesor de un nodo.
- **PUB-SUB (Publicación-Subscripción):** Para notificar eventos, como actualizaciones en el anillo o cambios de estado de nodos.

### Comunicación cliente-servidor y servidor-servidor
1. **Cliente-Servidor (Bootstrap):**
   - **REQ-REP:** El cliente solicita al bootstrap unirse al anillo y obtiene la información del nodo sucesor.
   - **Persistencia:** Las solicitudes no procesadas por fallos temporales serán reintentadas según un algoritmo de reintentos exponenciales.

2. **Servidor-Servidor (Nodos en Chord):**
   - **PUB-SUB:** Los nodos notifican eventos, como actualizaciones en sus tablas de dedos.
   - **REQ-REP:** Resoluciones de claves y búsqueda de sucesores.
   - **Asincronía:** Los mensajes pueden ser enviados independientemente de las respuestas, tolerando fallos momentáneos.

### Comunicación entre procesos
- Los nodos en una misma instancia utilizan **hilos** para gestionar subprocesos internos, como recepción de mensajes y mantenimiento de la Finger Table.
- **Persistencia Local:** Los procesos persisten datos en bases de datos locales (SQLite) para manejar mensajes pendientes y almacenar el estado del nodo.
- **Coordinación:** Subprocesos como los listeners y los mantenedores de la Finger Table se comunican mediante colas internas.
