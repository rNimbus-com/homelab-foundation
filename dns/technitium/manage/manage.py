import argparse
import json
import logging
import os
import requests
import sys
import yaml

parser = argparse.ArgumentParser(description='Manages DHCP and DNS entries')
parser.add_argument('-f','--var-file', help='Values file', required=True)
parser.add_argument('-t','--api-token', help='The API token for logging in to the Technitium API.', required=False)
parser.add_argument('-a','--api-host', help='The endpoint of Technitium API. If set, overrides api.hostname value in the values file.', required=False)
parser.add_argument('--dhcp', help='Only runs DHCP updates.', action='store_true')
loglevel_choices=list(dict.fromkeys([logging.getLevelName(l) for l in logging.getLevelNamesMapping().values()]))
parser.add_argument('--log-level', help='The log level. Defaults to INFO.', required=False, default="INFO", choices=loglevel_choices)
args = parser.parse_args()

VAR_FILE: str = args.var_file

with open(VAR_FILE, 'r') as var_file:
    VALUES = yaml.safe_load(var_file)

class ApiStatusError(Exception):
        """Exception raised a status type of "error" is returned from the Technitium API."""
        def __init__(self, message="Status type of error was found in the response."):
            super().__init__(message)

def get_api_token()-> str:
    """Gets the api token from various sources.
       
       Order of precedence is:
       1. stdin
       2. value from the --api-token argument
       3. TECHNITIUM_API_TOKEN environment variable, if set
    """
    api_token: str = ''
    if "TECHNITIUM_API_TOKEN" in os.environ:
        api_token = os.getenv("TECHNITIUM_API_TOKEN")
    
    if args.api_token:
        api_token = args.api_token

    if not sys.stdin.isatty():
        api_token = sys.stdin.read()
    
    if not api_token:
        raise SystemExit("API Token is required but not found in stdin, --api-token argument or a TECHNITIUM_API_TOKEN environment variable. One of these must be set!")

    return api_token

def get_api_host()-> str:
    """Gets the api host from various sources.
       
       Order of precedence is:
       1. Value of the --api-host argument
       2. api.hostname value from the values file
       3. TECHNITIUM_API_HOST environment variable, if set
    """
    api_host: str = ''
    if "TECHNITIUM_API_HOST" in os.environ:
        api_host = os.getenv("TECHNITIUM_API_HOST")
    
    if "api" in VALUES:
        if "hostname" in VALUES["api"]:
            api_host = VALUES["api"]["hostname"]

    if args.api_host:
        api_host = args.api_host
   
    if not api_host:
        raise SystemExit("API Host not found set with --api-host argument, api.hostname in the values file, or a TECHNITIUM_API_HOST environment variable. One of these must be set!")

    return api_host

type JSON = dict[str, "JSON"] | list["JSON"] | str | int | float | bool | None

def detect_api_status_error(response: JSON):
    """Raises an ApiStatusError if a status type of "error" is found in the response json. The API returns a status code of 200 in some cases, requiring this extra step.

    Args:
        response (JSON): API response to detect errors in
    """
    if "status" in response:
        if response["status"].casefold() == "error".casefold():
            raise ApiStatusError(response["errorMessage"])

def get_dhcp_scope(name: str, api_host: str, api_token: str) -> JSON:
    """Gets a DHCP scope from the Technitium API

    Args:
        name (str): DHCP Scope Name
        api_host (str): API endpoint (example: http://localhost:5380)
        api_token (str): Token used to authenticate against the api_host.

    Raises:
        RuntimeError: When API returns an error from the request.

    Returns:
        str: JSON response data for the requested DHCP scope.
    """
    url = f"{api_host}/api/dhcp/scopes/get"
    params = {'token': api_token, 'name': name}
    logging.info(f"Get scope {name} from {url}")
    response = requests.get(url, params=params)
    response.raise_for_status()
    data = response.json()

    logging.debug(json.dumps(data, indent=4))

    # API returns 200 response code even when no scope is found
    detect_api_status_error(data)
    
    return data

def validate_scopes(scopes: dict[str, dict], api_host: str, api_token: str):
    """Iterates through scopes and validates every scope exists.

    Args:
        scopes (dict[str, dict]): Dictionary of scopes and their values to check for.
        api_host (str): API endpoint (example: http://localhost:5380)
        api_token (str): Token used to authenticate against the api_host.
    """
    for scope in scopes:
        try:
            logging.info(f"Checking for dhcp scope: {scope["name"]}")
            dhcp_scope = get_dhcp_scope(scope["name"], api_host, api_token)            
        except ApiStatusError as r:
            logging.exception(f"API Response contained an error for dhcp scope '{scope["name"]}':", file=sys.stderr)
            raise(r)
        except requests.exceptions.HTTPError as httperr:
            logging.exception(f"Unexpected HTTPError for dhcp scope '{scope["name"]}':", file=sys.stderr)
            raise(httperr)
        except Exception as e:
            logging.exception(f"Unexpected Error for dhcp scope '{scope["name"]}':", file=sys.stderr)
            raise(e)

def get_dhcp_reservation(scope_name: str, hardware_address: str, api_host: str, api_token: str) -> JSON:
    """Gets an existing DHCP reservation for a hardware MAC address

    Args:
        scope_name (str): The scope containing a reservation for the hardware_address
        hardware_address (str): MAC address of the DHCP reservation
        api_host (str): API endpoint (example: http://localhost:5380)
        api_token (str): Token used to authenticate against the api_host.
    """
    url = f"{api_host}/api/dhcp/scopes/get"
    params = { "token": api_token, "name": scope_name }
    logging.info(f"Get DHCP reservation (MAC={hardware_address}; scope={scope_name}) from {url}")
    response = requests.get(url, params=params)
    response.raise_for_status()
    data = response.json()

    logging.debug(json.dumps(data, indent=4))

    # API returns 200 response code even when no scope is found
    detect_api_status_error(data)
    if "response" in data:
        if "reservedLeases" in data["response"]:
            leases = data["response"]["reservedLeases"]
            for lease in leases:
                if lease["hardwareAddress"].casefold() == hardware_address.casefold():
                    return lease
    return None

def delete_dhcp_reservation(scope_name: str, hardware_address: str, api_host: str, api_token: str) -> JSON:
    """Deletes an existing DHCP reservation for a hardware MAC address in a specific scope

    Args:
        scope_name (str): The scope containing a reservation for the hardware_address 
        hardware_address (str): MAC address of the DHCP reservation to delete
        api_host (str): API endpoint (example: http://localhost:5380)
        api_token (str): Token used to authenticate against the api_host.
    """
    url = f"{api_host}/api/dhcp/scopes/removeReservedLease"
    params = { 
        "token": api_token,
        "name": scope_name,
        "hardwareAddress": hardware_address
    }
    logging.info(f"Delete DHCP reservation (MAC={hardware_address}; scope={scope_name}) at {url}")
    response = requests.post(url, params=params)
    response.raise_for_status()
    data = response.json()
    logging.debug(json.dumps(data, indent=4))

    # API returns 200 response code even when no scope is found
    detect_api_status_error(data)
    
    return data

def add_dhcp_reservation(scope_name: str, hardware_address: str, ip_address: str, api_host: str, api_token: str, host_name: str = "", comments: str = "") -> JSON:
    """Sets a DHCP scope for the assignment

    Args:
        scope_name (str): The scope name in which to make reserved lease
        hardware_address (str): The MAC address of the client.
        ip_address (str): The reserved IP address for the client.
        api_host (str): API endpoint (example: http://localhost:5380).
        api_token (str): Token used to authenticate against the api_host.
        host_name (str): (Optional) The hostname of the client to override.
        comments (str): (Optional) Comments for the reserved lease entry.
    """
    url = f"{api_host}/api/dhcp/scopes/addReservedLease"
    params = {
        "token": api_token, 
        "name": scope_name,
        "hardwareAddress": hardware_address,
        "ipAddress": ip_address,
        "hostName": host_name,
        "comments": "managed by pyTechnitium"
    }
    if comments:
        params["comments"] = f"{comments} -: {params["comments"]}"
        
    logging.info(f"Adding DHCP Reservation (MAC={hardware_address}; IP={ip_address}) ")
    response = requests.post(url, params=params)
    response.raise_for_status()
    data = response.json()
    logging.debug(json.dumps(data, indent=4))

    # API returns 200 response code even when no scope is found
    detect_api_status_error(data)
    
    return data

def set_dhcp_scope_reservations(dhcp_scopes: dict[str, dict], api_host: str, api_token: str):
    """Configures DHCP leases based on the dictionary of scope assignments

    Args:
        dhcp_scopes (dict[str, dict]): List of dhcp scopes and their address reservations
        api_host (str): API endpoint (example: http://localhost:5380)
        api_token (str): Token used to authenticate against the api_host.
    """
    for scope in dhcp_scopes:
        logging.info(f"Processing address reservations for scope: {scope["name"]}")
        for assignment in scope.get("assignments", []):
            mac_address = str.replace(assignment["hardwareAddress"], ":", "-")
            exising_reservation = get_dhcp_reservation(scope["name"], mac_address, api_host, api_token)
            if exising_reservation:
                logging.info(f"Removing existing reservation for MAC {mac_address}.")
                delete_dhcp_reservation(scope["name"], mac_address, api_host, api_token)
            add_dhcp_reservation(scope["name"], 
                                mac_address, 
                                assignment["ipAddress"],
                                api_host,
                                api_token,
                                assignment.get("hostName", ""),
                                assignment.get("comments", ""))
            
def get_dhcp_scope(name: str, api_host: str, api_token: str) -> JSON:
    """Gets a DHCP scope from the Technitium API

    Args:
        name (str): DHCP Scope Name
        api_host (str): API endpoint (example: http://localhost:5380)
        api_token (str): Token used to authenticate against the api_host.

    Raises:
        RuntimeError: When API returns an error from the request.

    Returns:
        str: JSON response data for the requested DHCP scope.
    """
    url = f"{api_host}/api/dhcp/scopes/get"
    params = {'token': api_token, 'name': name}
    logging.info(f"Requesting scope {name} from {url}")
    response = requests.get(url, params=params)
    response.raise_for_status()
    data = response.json()
    logging.debug(json.dumps(data, indent=4))

    # API returns 200 response code even when no scope is found
    detect_api_status_error(data)
    
    return data

def validate_scopes(scopes: dict[str, dict], api_host: str, api_token: str):
    """Iterates through scopes and validates every scope exists.

    Args:
        scopes (dict[str, dict]): Dictionary of scopes and their values to check for.
        api_host (str): API endpoint (example: http://localhost:5380)
        api_token (str): Token used to authenticate against the api_host.
    """
    for scope in scopes:
        try:
            logging.info(f"Checking for dhcp scope: {scope["name"]}")
            dhcp_scope = get_dhcp_scope(scope["name"], api_host, api_token)
        except ApiStatusError as r:
            logging.info(f"API Response contained an error for dhcp scope '{scope["name"]}':", file=sys.stderr)
            raise(r)
        except requests.exceptions.HTTPError as httperr:
            logging.info(f"Unexpected HTTPError for dhcp scope '{scope["name"]}':", file=sys.stderr)
            raise(httperr)
        except Exception as e:
            logging.info(f"Unexpected Error for dhcp scope '{scope["name"]}':", file=sys.stderr)
            raise(e)

def get_dns_zone_options(zone: str, api_host: str, api_token: str) -> JSON:
    """Gets Zone Options for an authoritative zone from the Technitium API

    Args:
        zone (str): DNZ Zone Name
        api_host (str): API endpoint (example: http://localhost:5380)
        api_token (str): Token used to authenticate against the api_host.

    Raises:
        RuntimeError: When API returns an error from the request.

    Returns:
        str: JSON response data for the requested Zone options.
    """

    url = f"{api_host}/api/zones/options/get"
    params = {
        "token": api_token, 
        "zone": zone,
        "includeAvailableCatalogZoneNames": "true",
        "includeAvailableTsigKeyNames": "true"
    }
    logging.info(f"Requesting zone options for zone {zone} from {url}")
    response = requests.get(url, params=params)
    response.raise_for_status()
    data = response.json()
    logging.debug(json.dumps(data, indent=4))

    # API returns 200 response code even when no scope is found
    detect_api_status_error(data)
    
    return data

def add_dns_zone_record(zone: str, name: str, record_type: str, api_host: str, api_token: str, ip_address: str | None = None, name_server: str | None = None, cname: str | None = None, overwrite: bool = False, ptr: bool = False, create_ptr_zone: bool = False) -> JSON:
    """Gets Zone Options for an authoritative zone from the Technitium API

    Args:
        zone (str): DNS Zone Name
        name (str): Name of the record to add.
        record_type (str): Record type: A, AAAA, NS, CNAME, etc
        api_host (str): API endpoint (example: http://localhost:5380)
        api_token (str): Token used to authenticate against the api_host.
        ip_address (str): (Conditional) Required for A or AAAA record types, otherwise should not be set.
        cname (str): (Conditional) Required for CNAME record type, otherwise should not be set.
        overwrite (bool): (Optional) Creates or updates existing record. false: Creates new records only.
        ptr (bool): (Optional) Creates a reverse PTR record for the ipAddress. This option is used only for A and AAAA records.
        create_ptr_zone (bool): (Optional) Creates a new Ptr Zone for the ip address if it doesn't exist. false: expects PTR zone to already exist if ptr=true.
    Raises:
        RuntimeError: When API returns an error from the request.

    Returns:
        str: JSON response data for the requested Zone options.
    """

    url = f"{api_host}/api/zones/records/add"
    params = {
        "token": api_token, 
        "zone": zone,
        "domain": f"{name}.{zone}",
        "type": record_type,
        "overwrite": overwrite,
        "ptr": ptr,
        "createPtrZone": create_ptr_zone,
        "comments": "managed by pyTechnitium"
    }

    if record_type.upper() in { "A", "AAAA" }:
        if ip_address is None:
            raise ValueError(f"ip_address must be set for record_type {record_type.upper()}")
        params["ipAddress"] = ip_address
    elif ip_address:
        logging.warning(f"ip_address is set but is not valid for record type {record_type.upper()} and will be ignored")

    if record_type.upper() == "CNAME":
        if cname is None:
            raise ValueError(f"cname must be set for record_type {record_type.upper()}")
        params["cname"] = cname
    elif cname:
        logging.warning(f"cname is set but is not valid for record type {record_type.upper()} and will be ignored")

    if record_type.upper() == "NS":
        if name_server is None:
            raise ValueError(f"name_server must be set for record_type {record_type.upper()}")
        params["name_server"] = cname
    elif name_server:
        logging.warning(f"name_server is set but is not valid for record type {record_type.upper()} and will be ignored")

    logging.info(f"Adding/Updating {name}.{zone} {record_type.upper()} record to {url}")
    response = requests.post(url, params=params)
    response.raise_for_status()
    data = response.json()
    logging.debug(json.dumps(data, indent=4))

    if "status" in data:
        if data["status"].casefold() == "error".casefold():
            logging.info("detected error in response")
            if data["errorMessage"].casefold() == "cannot add record: record already exists.".casefold():
                logging.info("error expected")
                if not overwrite:
                    logging.info("overriding error")
                    data["status"] = "ok"
                    data["message"] = "Record not added. Record already exists."
                    del data["errorMessage"]
                    return data
        
    # API returns 200 response code even when there was an error
    detect_api_status_error(data)
    
    return data

def validate_dns_zones(zones: dict[str, dict], api_host: str, api_token: str):
    """Iterates through zones and validates every zone exists.

    Args:
        zones (dict[str, dict]): Dictionary of zones and their values to check for.
        api_host (str): API endpoint (example: http://localhost:5380)
        api_token (str): Token used to authenticate against the api_host.
    """
    for zone in zones:
        try:
            logging.info(f"Checking for dns zone: {zone["zone"]}")
            zone_options = get_dns_zone_options(zone["zone"], api_host, api_token)
        except ApiStatusError as r:
            logging.exception(f"API Response contained an error for dns zone '{zone["zone"]}':", file=sys.stderr)
            raise(r)
        except requests.exceptions.HTTPError as httperr:
            logging.exception(f"Unexpected HTTPError for dns zone '{zone["zone"]}':", file=sys.stderr)
            raise(httperr)
        except Exception as e:
            logging.exception(f"Unexpected Error for dns zone '{zone["zone"]}':", file=sys.stderr)
            raise(e)

def set_dns_zone_records(dns_zones: dict[str, dict], api_host: str, api_token: str):
    """Configures DHCP leases based on the dictionary of scope assignments

    Args:
        dns_zones (dict[str, dict]): List of dns zones and their records
        api_host (str): API endpoint (example: http://localhost:5380)
        api_token (str): Token used to authenticate against the api_host.
    """
    for zone in dns_zones:
        logging.info(f"Processing DNS records for zone: {zone["zone"]}")
        for record in zone.get("records", []):
            add_dns_zone_record(zone["zone"],
                                record["name"],
                                record["type"],
                                api_host,
                                api_token,
                                record.get("ipAddress", None),
                                record.get("nameServer", None),
                                record.get("cname", None),
                                record.get("overwrite", False),
                                record.get("ptr", False),
                                record.get("createPtrZone", False))
            
def main():
    numeric_level = getattr(logging, args.log_level, None)
    logging.basicConfig(level=numeric_level)
    API_TOKEN: str = get_api_token()
    API_HOST: str = get_api_host()
    logging.info(f"API_HOST: {API_HOST}")

    if "zones" in VALUES and not args.dhcp:
        validate_dns_zones(VALUES["zones"], API_HOST, API_TOKEN)
        set_dns_zone_records(VALUES["zones"], API_HOST, API_TOKEN)

    if "dhcp_scopes" in VALUES:
        validate_scopes(VALUES["dhcp_scopes"], API_HOST, API_TOKEN)
        set_dhcp_scope_reservations(VALUES["dhcp_scopes"], API_HOST, API_TOKEN)


main()