#!/bin/bash

if ! command -v docker &> /dev/null
then
    echo "Docker no está instalado. Por favor, instálalo antes de continuar."
    exit 1
fi
if ! command -v docker-compose &> /dev/null
then
    echo "Docker Compose no está instalado. Por favor, instálalo antes de continuar."
    exit 1
fi

echo "Construyendo la imagen del router..."
docker build -t router-image -f Dockerfile.router .
if [ $? -ne 0 ]; then
    echo "Error al construir la imagen del router."
    exit 1
fi

echo "Construyendo la imagen del servidor..."
docker build -t server-image -f Dockerfile.server .
if [ $? -ne 0 ]; then
    echo "Error al construir la imagen del servidor."
    exit 1
fi

echo "Construyendo la imagen del cliente..."
docker build -t client-image -f Dockerfile.client .
if [ $? -ne 0 ]; then
    echo "Error al construir la imagen del cliente."
    exit 1
fi

echo "Levantando los contenedores con Docker Compose..."
docker-compose up -d
if [ $? -ne 0 ]; then
    echo "Error al levantar los contenedores con Docker Compose."
    exit 1
fi

echo "La red ha sido montada con exito."
