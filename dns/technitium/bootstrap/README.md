# Technitium DNS Container

Bootstraps a new Technitium dns-server in a docker container and configures it for use. These scripts should only need to be ran once, as they will overwrite existing configurations.

## PreReqs
- A debian or ubuntu host with sudo access capable of running docker engine.
- For non-DHCP installations: The IP Address of the host assigned by your router / dhcp.
- For DHCP installations: Host with IP Address statically configured.

## .env configuration

Configure a new `environments/{environment}.env` file using `environments/example.env` as a starting template. Contains values that are used to create and configure the DNS server. Review each setting, likely updating `DNS_ZONE` and `DNS_HOST_IP` at a minimum. This file will not be added to git by default.


environments/{environment}.env
```
API_HOSTNAME='http://localhost:5380' # The address hosting (or will host) the API endpoint. 'http://localhost:5380' by default.
ADMIN_USER='admin'                   # The default admin user name. This is `admin` by default.
API_TOKEN_NAME='Automation'          # Name given to the token. Doesn't really matter. Can view tokens by name in UI or API (but not their values)
DNS_ZONE='local.example.com'         # The zone to create and manage for your network
DNS_SERVER_NAME='dns1'               # The name of the DNS server and DNS record to create in the DNS_ZONE.
DNS_HOST_IP='192.168.0.6'            # This is usually the IP address assigned to the docker HOST.
DHCP_ENABLED='false'                 # Enabled DHCP service. If set, changes network_mode to 'host' and unsets SYS_CTLS
EXPORT_API_TOKEN='false'             # Adds/Updates .profile with an 'export TECHNITIUM_API_TOKEN=xxx' statement

# DHCP Settings (Required if DHCP_ENABLED=true)
DHCP_SCOPE_NAME='local.example.com'
DHCP_ASSIGNMENT_RANGE='192.168.0.1|192.168.1.254'
DHCP_SUBNET_MASK='255.255.254.0'
DHCP_ROUTER_ADDRESS='192.168.0.1'
DHCP_EXCLUSION_RANGE='' # Set this to exclude addresses from being assigned from this range. Format: {startingIp}|{endingIP} ex: 192.168.0.1|192.168.0.255
DHCP_LEASE_TIME_DAYS=1
DHCP_LEASE_TIME_HOURS=0   # Must be between 0 and 23
DHCP_LEASE_TIME_MINUTES=0 # Must be between 0 and 59
DHCP_ALLOW_DNS_UPDATES='true'
DHCP_DNS_TTL=900
DHCP_BOOT_FILE_NAME=''
DHCP_DOMAIN_SEARCH_LIST=''
DHCP_IGNORE_CLIENT_IDENTIFIER_OPTION='true'
DHCP_RESERVED_LEASES='myrouter|17:84:26:65:a4:b9|192.168.0.1|Router MAC address'
```

## Scripts

The scripts below are to be ran in order to configure the host machine and install and configure a Technitium dns-server as a docker container. All scripts can be re-ran at any time, but those marked "one-time" only need to be ran for the initial installation.

### 1. init.sh (one-time)

`init.sh` only needs to be executed once on the host machine.
- Installs Docker
- Installs additional prereqs required by later scripts.
- **!! Host needs to be restarted after first run to avoid docker permission errors !!**

### 2. configure.sh (one-time)

`configure.sh` calls the `configure-auth.sh` and `configure-zones.sh` scripts sequentially to start the docker container and configure the DNS server. Expects environment variables in the `environments/{environment}.env` file to be set. Requires an additional `DNS_ADMIN_PASSWORD` value be set in addition to those in the .env file.

- Validates login with admin credentials.
- If `admin` password is set to the default `admin` then sets a new password to the value configured for `DNS_ADMIN_PASSWORD`.
- Creates a new Technitium DNS API Token and outputs the result.
- Creates a new zone as set in the `DNS_ZONE` variable.
- Creates or updates a `DNS_SERVER_NAME` A record in the `DNS_ZONE` mapped to the `DNS_HOST_IP`.
- Creates a new Technitium DNS API Token and outputs the result.
- When `DHCP_ENABLED=true` is set enables DHCP under a new scope.

configure.sh
```
## Replace password value with your desired admin password

DNS_ADMIN_PASSWORD='1242!14lksaDjrfe@skL' ./configure.sh

```

sourced configure.sh
```
## exports the generated API key to a TECHNITIUM_API_TOKEN variable.
## Replace password value with your desired admin password

DNS_ADMIN_PASSWORD='1242!14lksaDjrfe@skL' source ./configure.sh
```



#### a. configure-auth.sh (one-time)

**!!Important** Scripts listed under sections a, b and c only need to be ran if you skipped running `configure.sh`

- Validates login with admin credentials.
- If `admin` password is set to the default `admin` then sets a new password to the value configured for `DNS_ADMIN_PASSWORD`
- Creates a new Technitium DNS API Token and outputs the result.

configure-auth.sh
```
# Configures a new admin password and api token. Change the DNS_ADMIN_PASSWORD prior to running.

# Load environment variables
set -o allexport && source environments/{environment}.env && set +o allexport

# set an admin password and execute the configure-auth.sh script
DNS_ADMIN_PASSWORD='1242!14lksaDjrfe@skL' ./configure-auth.sh
```

#### b. configure-zones.sh (one-time)

**!!Important** Scripts listed under sections a, b and c only need to be ran if you skipped running `configure.sh`

Requires values be set correctly in the `environments/{environment}.env` file.

- Creates a new zone as set in the `DNS_ZONE` variable.
- Creates or updates a `DNS_SERVER_NAME` A record in the `DNS_ZONE` mapped to the `DNS_HOST_IP`.
- Creates a new Technitium DNS API Token and outputs the result.

configure-zones.sh
```
# Configures your zone and A record for your DNS server.

# Load environment variables
set -o allexport && source environments/{environment}.env && set +o allexport

# set a valid Api Token and execute the ./configure-zones.sh script
TECHNITIUM_API_TOKEN=6a105966a27eb88c5f6fa5dfb24c701b83de711a7f0bf33c23a5d93ec1a6d86a ./configure-zones.sh

```

#### c. configure-dhcp.sh (one-time)

**!!Important** Scripts listed under sections a, b and c only need to be ran if you skipped running `configure.sh`

Requires values be set correctly in the `environments/{environment}.env` file.

- Requires `DHCP_ENABLED=true` set.
- Creates a new DHCP scope using values set in your `environments/{environment}.env` file.

configure-dhcp.sh
```
# Configures a new DHCP scope.

# Load environment variables
set -o allexport && source environments/{environment}.env && set +o allexport

# set a valid Api Token and execute the ./configure-dhcp.sh script
TECHNITIUM_API_TOKEN=6a105966a27eb88c5f6fa5dfb24c701b83de711a7f0bf33c23a5d93ec1a6d86a ./configure-dhcp.sh

```

### 3. upgrade.sh

`upgrade.sh` (formerly `restart.sh`) upgrades the Technitium dns-server container to the latest published image: it takes the container down, removes the local `technitium/dns-server:latest` image, and brings it back up, which forces a fresh pull from Docker Hub.

- Pulling `:latest` is intentional -- this script is the upgrade mechanism. Do not pin the image tag in `docker-compose.yml`.
- To restart the container without upgrading, use `docker restart technitium-dns-server`.
- Expects environment variables in the `environments/{environment}.env` file (only `DNS_SERVER_NAME` and related values are used for the status output).

## Post Install Steps

- Save the value of the TECHNITIUM_API_TOKEN somewhere secure if you plan on using it in the future (requires the `configure.sh` or `configure-auth.sh` be sourced)
  `echo $TECHNITIUM_API_TOKEN`
- Save the value of the DNS_ADMIN_PASSWORD somewhere secure if you haven't already
- Renew dhcp leases or reboot network clients to pull new DNS configuration. Make sure to save any passwords / tokens above if rebooting this host!
- Login to your DNS server's web UI using the credentials set by this script. Output with command below or check your `environments/{environment}.env` file.
  ```
    set -o allexport && source environments/{environment}.env && set +o allexport
    echo "Web UI: http://${DNS_SERVER_NAME}.${DNS_ZONE}:5380
  ```
- Review [../manage/README.md](../manage/README.md) for ongoing configuration and managment of DNS and DHCP services (if enabled).

### DHCP

Post installation steps differ depending on your DHCP configuration.

**DHCP Server disabled (default):**

- Configure DHCP in your router / dhcp server to assign a reserved/static IP Address to this host. Check `environments/{environment}.env` file or echo the environment variable if you forgot what you set it to.
  ```
    set -o allexport && source environments/{environment}.env && set +o allexport
    echo $DNS_HOST_IP
  ```

**DHCP Server enabled:**

- Make sure other DHCP servers are disabled (i.e router).
- If you haven't already, configure a static IP for the host machine.
```
# Configures a Static IP for when this host will not be a DHCP client, probably because it's a DHCP server.
# Check output of 'sudo nmcli -p connection show' for network interface name
interface_name='Wired connection 1'
# Set static ip to an available IP address for your network and include the CIDR
static_ip_cidr='192.168.0.2/24'
# Set the gateway to your router IP address
gateway='192.168.0.1'
# Set DNS servers to localhost.
dns_servers='127.0.0.1' # After DNS Server is up and running

# Configures interface to use a static IP address
sudo nmcli c mod "$interface_name" ipv4.addresses $static_ip_cidr ipv4.method manual
# Configures interface's gateway
sudo nmcli con mod "$interface_name" ipv4.gateway $gateway
# Configures interface's DNS Servers
sudo nmcli con mod "$interface_name" ipv4.dns "$dns_servers"
# Restarts the network interface
sudo nmcli c down "$interface_name" && sudo nmcli c up "$interface_name"
# Note: will probably also need to restart Docker after this is done if you did this after docker was up and running.
sudo systemctl restart docker
```