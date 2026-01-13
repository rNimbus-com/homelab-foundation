#! /bin/bash
set -e

if [[ -z "$1" ]]; then
    echo "An environment file argument is required by this script."
    echo "  usage: ./restart.sh environments/example.env"
    exit 1
fi

env_file="$1"

set -o allexport && source ${env_file} && set +o allexport

if [[ -z ${API_HOSTNAME+x} ]] || [[ -z ${ADMIN_USER+x} ]] || [[ -z ${API_TOKEN_NAME+x} ]] || [[ -z ${DNS_ZONE+x} ]] || [[ -z ${DNS_SERVER_NAME+x} ]] || [[ -z ${DNS_HOST_IP+x} ]]; then
    echo "Environment variables not configured properly. Required variables:"
    echo "  API_HOSTNAME: http endpoint of the host (usually http://localhost:5380)"
    echo "  ADMIN_USER: Admin user name (usually admin)"
    echo "  API_TOKEN_NAME: Name for the API token (usually Automation)"
    echo "  DNS_ZONE: The DNS Zone (example: local.example.com)"
    echo "  DNS_SERVER_NAME: The host name for the DNS server (example: dns1)"
    echo "  DNS_HOST_IP: The DNS server's host IP address (example: 192.168.0.6)"
    exit 1
fi

# Start the docker container
compose_file="docker-compose.yml"
if [[ "${DHCP_ENABLED}" == 'true' ]]; then
    compose_file="docker-compose.dhcp.yml"
fi

if [ "$(docker inspect -f {{.State.Running}} technitium-dns-server)" == "true" ]; then
    docker compose -f "$compose_file" down
    docker image rm technitium/dns-server
    docker compose -f "$compose_file" up -d
else
    docker image rm technitium/dns-server --force
    docker compose -f "$compose_file" up -d
    echo "Waiting for technitium-dns-server container to start"
    sleep 5
    until [ "$(docker inspect -f {{.State.Running}} technitium-dns-server)" == "true" ]; do
        sleep 0.1;
    done;
fi

echo
echo "## Container technitium-dns-server started / restarted ##"
echo "   - DNS Server: $DNS_HOST_IP"
echo "   - Web UI: http://${DNS_SERVER_NAME}.${DNS_ZONE}:5380"