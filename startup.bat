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

echo Construyendo la imagen del router...
docker build -t router-image -f Dockerfile.router .
if %ERRORLEVEL% neq 0 (
    echo Error al construir la imagen del router.
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

echo Levantando los contenedores con Docker Compose...
docker-compose up -d
if %ERRORLEVEL% neq 0 (
    echo Error al levantar los contenedores con Docker Compose.
    exit /b 1
)

echo La red ha sido montada con exito.
pause
