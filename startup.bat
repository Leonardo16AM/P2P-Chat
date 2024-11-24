@echo off

where docker >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo Docker no está instalado. Por favor, instálalo antes de continuar.
    exit /b 1
)

where docker-compose >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo Docker Compose no está instalado. Por favor, instálalo antes de continuar.
    exit /b 1
)

echo Construyendo la imagen del servidor...
docker build -t server-image -f Dockerfile.server .
if %ERRORLEVEL% neq 0 (
    echo Error al construir la imagen del servidor.
    exit /b 1
)

echo Construyendo la imagen del cliente...
docker build -t client-image -f Dockerfile.client .
if %ERRORLEVEL% neq 0 (
    echo Error al construir la imagen del cliente.
    exit /b 1
)

echo Creando la red de Docker...
docker network create --subnet=192.168.1.0/24 chat_network
if %ERRORLEVEL% neq 0 (
    echo Error al crear la red de Docker. Es posible que ya exista.
)

echo Levantando los contenedores con Docker Compose...
docker-compose up -d
if %ERRORLEVEL% neq 0 (
    echo Error al levantar los contenedores con Docker Compose.
    exit /b 1
)

echo RED MONTADA CON EXITO
pause
