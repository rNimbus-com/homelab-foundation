#! /bin/bash
set -e

main() {
    # Optional environment file
    env_file="$1"
    if [[ ! -z ${env_file+x} ]]; then
        set -o allexport && source "$env_file" && set +o allexport
    fi
    # Ensure ENV vars are set / read in properly
    assert_env_vars_valid

    # Build the image
    echo "INFO: Starting service"
    docker compose up -d
}

assert_env_vars_valid(){
    # Asserts environment variables required by this script are valid

    if [[ -z ${CLOUDFLARE_DNS_API_TOKEN+x} ]]; then
        echo "ERROR: CLOUDFLARE_DNS_API_TOKEN not set or empty but is required by this script. Ensure it is included in the .env file or exported prior to running this script." >&2
        echo "         export:" >&2
        echo "           $ export CLOUDFLARE_DNS_API_TOKEN='xxxxx'" >&2
        echo "           $ ./compose.sh" >&2
        echo "        inline:" >&2
        echo "          $ CLOUDFLARE_DNS_API_TOKEN='xxxxx' ./compose.sh" >&2
        exit 1
    fi
}

main "$@"