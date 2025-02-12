#!/bin/bash

# Solicita al usuario que ingrese una opción.
read -p "Presiona Enter para solo copiar archivos y reiniciar contenedores, o escribe 'build' para un build completo: " choice

if [ -z "$choice" ]; then
    echo "Reiniciando completamente los contenedores..."
    docker stop client1 client2 client3 server1 server2 server3 router
    docker rm client1 client2 client3 server1 server2 server3 router

    echo "Levantando contenedores..."
    docker-compose up -d

    echo "Copiando archivos actualizados..."
    docker cp ./client client1:/app
    docker cp ./client client2:/app
    docker cp ./client client3:/app
    docker cp ./server server1:/app
    docker cp ./server server2:/app
    docker cp ./server server3:/app

    echo "Contenedores actualizados y reiniciados correctamente."
    exit 0

elif [ "$choice" == "build" ]; then
    echo "Realizando build completo..."
    docker stop client1 client2 client3 server1 server2 server3 router
    docker rm client1 client2 client3 server1 server2 server3 router

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

    echo "Build completo realizado y red levantada con éxito."
    read -n 1 -s -r -p "Presiona cualquier tecla para continuar..."
    echo
    exit 0

else
    echo "Opción inválida. Por favor, inténtalo nuevamente."
    read -n 1 -s -r -p "Presiona cualquier tecla para continuar..."
    echo
    exit 1
fi
