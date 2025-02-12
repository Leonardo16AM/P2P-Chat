@echo off
set /p choice="Presiona Enter para solo copiar archivos y reiniciar contenedores, o escribe 'build' para un build completo: "

if "%choice%"=="" (
    echo Reiniciando completamente los contenedores...
    docker stop client1 client2 client3 server1 server2 server3 router
    docker rm client1 client2 client3 server1 server2 server3 router

    echo Levantando contenedores...
    docker-compose up -d

    echo Copiando archivos actualizados...
    docker cp ./client client1:/app
    docker cp ./client client2:/app
    docker cp ./client client3:/app
    docker cp ./server server1:/app
    docker cp ./server server2:/app
    docker cp ./server server3:/app

    echo Contenedores actualizados y reiniciados correctamente.
    exit /b
)

if "%choice%"=="build" (
    echo Realizando build completo...
    docker stop client1 client2 client3 server1 server2 server3 router
    docker rm client1 client2 client3 server1 server2 server3 router

    docker build -t router-image -f Dockerfile.router .
    if %ERRORLEVEL% neq 0 (
        echo Error al construir la imagen del router.
        exit /b 1
    )

    docker build -t server-image -f Dockerfile.server .
    if %ERRORLEVEL% neq 0 (
        echo Error al construir la imagen del servidor.
        exit /b 1
    )

    docker build -t client-image -f Dockerfile.client .
    if %ERRORLEVEL% neq 0 (
        echo Error al construir la imagen del cliente.
        exit /b 1
    )

    docker-compose up -d --build
    if %ERRORLEVEL% neq 0 (
        echo Error al levantar los contenedores con Docker Compose.
        exit /b 1
    )

    echo Build completo realizado y red levantada con exito.
    pause
    exit /b
)

echo Opcion invalida. Por favor, intentalo nuevamente.
pause
