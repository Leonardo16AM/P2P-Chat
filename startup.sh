#!/bin/bash

read -p "Presiona Enter para solo copiar archivos y reiniciar contenedores, o escribe 'build' para un build completo: " choice

if [ "$choice" == "" ]; then
    echo "Reiniciando completamente los contenedores..."
    docker stop client1 client2 client3 server router
    docker rm client1 client2 client3 server router

    echo "Copiando archivos actualizados..."
    docker cp ./client client1:/app
    docker cp ./client client2:/app
    docker cp ./client client3:/app
    docker cp ./server server:/app

    echo "Levantando contenedores..."
    docker-compose up -d
    echo "Contenedores actualizados y reiniciados correctamente."
    exit 0
fi

if [ "$choice" == "build" ]; then
    echo "Realizando build completo..."
    docker stop client1 client2 client3 server router
    docker rm client1 client2 client3 server router

    docker build -t router-image -f Dockerfile.router .
    if [ $? -ne 0 ]; then
        echo "Error al construir la imagen del router."
        exit 1
    fi

    docker build -t server-image -f Dockerfile.server .
    if [ $? -ne 0 ]; then
        echo "Error al construir la imagen del servidor."
        exit 1
    fi

    docker build -t client-image -f Dockerfile.client .
    if [ $? -ne 0 ]; then
        echo "Error al construir la imagen del cliente."
        exit 1
    fi

    docker-compose up -d --build
    if [ $? -ne 0 ]; then
        echo "Error al levantar los contenedores con Docker Compose."
        exit 1
    fi

    echo "Build completo realizado y red levantada con exito."
    exit 0
fi

echo "Opcion invalida. Por favor, intentalo nuevamente."
