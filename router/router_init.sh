#!/bin/sh

# Habilitar el reenvío de IP
echo "Habilitando el reenvío de IP..."
sysctl -w net.ipv4.ip_forward=1

# Limpiar las reglas existentes de iptables
echo "Limpiando las reglas existentes de iptables..."
iptables -F
iptables -t nat -F
iptables -X
iptables -t nat -X

# Determinar las interfaces asociadas con las redes Docker
echo "Determinando las interfaces de red..."
SERVER_INTERFACE=$(ip route | grep "192.168.1.0/24" | awk '{print $3}')
CLIENT_INTERFACE=$(ip route | grep "192.168.2.0/24" | awk '{print $3}')

echo "Interfaz del servidor: $SERVER_INTERFACE"
echo "Interfaz del cliente: $CLIENT_INTERFACE"

# Validar que se encontraron las interfaces
if [ -z "$SERVER_INTERFACE" ] || [ -z "$CLIENT_INTERFACE" ]; then
  echo "Error: No se pudieron determinar las interfaces de red. Saliendo."
  exit 1
fi

# Configurar las reglas de reenvío
echo "Configurando reglas de reenvío..."
# Permitir tráfico de CLIENT a SERVER
iptables -A FORWARD -i "$CLIENT_INTERFACE" -o "$SERVER_INTERFACE" -s 192.168.2.0/24 -d 192.168.1.0/24 -j ACCEPT
# Permitir tráfico establecido y relacionado de SERVER a CLIENT
iptables -A FORWARD -i "$SERVER_INTERFACE" -o "$CLIENT_INTERFACE" -m state --state ESTABLISHED,RELATED -j ACCEPT

# Identificar la interfaz que conecta a Internet
echo "Identificando la interfaz de Internet..."
INTERNET_INTERFACE=$(ip route | grep default | awk '{print $5}')

echo "Interfaz de Internet: $INTERNET_INTERFACE"

if [ -z "$INTERNET_INTERFACE" ]; then
  echo "Error: No se pudo determinar la interfaz de Internet. Saliendo."
  exit 1
fi

# Aplicar MASQUERADE solo para el tráfico que va hacia Internet
echo "Aplicando MASQUERADE solo para tráfico hacia Internet..."
iptables -t nat -A POSTROUTING -o "$INTERNET_INTERFACE" -j MASQUERADE

# Permitir tráfico DNS entre redes internas
echo "Asegurando el tráfico DNS..."
iptables -A FORWARD -i "$CLIENT_INTERFACE" -o "$SERVER_INTERFACE" -p udp --dport 53 -j ACCEPT
iptables -A FORWARD -i "$CLIENT_INTERFACE" -o "$SERVER_INTERFACE" -p tcp --dport 53 -j ACCEPT

# Asegurar que el tráfico DDNS hacia y desde 192.168.1.10 funcione correctamente
echo "Asegurando el tráfico DDNS hacia y desde 192.168.1.10..."
# Definir el puerto utilizado por DDNS
DDNS_PORT=8245  # Reemplaza con el puerto correcto si es diferente

# Permitir tráfico entrante al DDNS desde la red cliente
iptables -A FORWARD -i "$CLIENT_INTERFACE" -o "$SERVER_INTERFACE" -d 192.168.1.10 -p tcp --dport "$DDNS_PORT" -j ACCEPT
iptables -A FORWARD -i "$CLIENT_INTERFACE" -o "$SERVER_INTERFACE" -d 192.168.1.10 -p udp --dport "$DDNS_PORT" -j ACCEPT

# Permitir tráfico saliente desde el DDNS hacia la red cliente (respuestas)
iptables -A FORWARD -i "$SERVER_INTERFACE" -o "$CLIENT_INTERFACE" -s 192.168.1.10 -p tcp --sport "$DDNS_PORT" -j ACCEPT
iptables -A FORWARD -i "$SERVER_INTERFACE" -o "$CLIENT_INTERFACE" -s 192.168.1.10 -p udp --sport "$DDNS_PORT" -j ACCEPT

# Opcional: Permitir tráfico ICMP (ping) entre redes
echo "Permitiendo tráfico ICMP (ping) entre redes..."
iptables -A FORWARD -i "$CLIENT_INTERFACE" -o "$SERVER_INTERFACE" -p icmp -j ACCEPT
iptables -A FORWARD -i "$SERVER_INTERFACE" -o "$CLIENT_INTERFACE" -p icmp -j ACCEPT

# Opcional: Registrar intentos de conexión para depuración
# echo "Registrando intentos de conexión..."
# iptables -A FORWARD -j LOG --log-prefix "IPTables-FORWARD: " --log-level 4

# Información de depuración
echo "Reglas actuales de iptables (FILTER):"
iptables -L -v -n
echo "Reglas NAT actuales:"
iptables -t nat -L -v -n

# Mantener el contenedor en ejecución
echo "Configuración del router completada. Manteniendo el contenedor en ejecución..."
tail -f /dev/null
