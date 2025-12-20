#! /bin/bash
set -e

# Tracks the temporary merged artifacts directory
tmp_artifacts_dir=''

main() {
    assert_args_are_valid "$@"
    
    # Load environment file
    env_file="$1"
    echo "INFO: exporting environment variables from file \"$env_file\""
    set -o allexport && source "$env_file" && set +o allexport
    
    # Ensure ENV vars are set / read in properly
    assert_env_vars_valid

    # Prepare artifacts for the image
    echo "INFO: Preparing image artifacts"
    prepare_artifacts

    # Build the image
    echo "INFO: Building docker image nginx/proxy:latest..."
    docker build --build-arg IMAGE_ARTIFACTS_PATH="${tmp_artifacts_dir}" \
        --build-arg CERTBOT_CONFIG_FILE="/opt/certbot-config/${CERTBOT_CONFIG_FILE_NAME}" \
        -t ${IMAGE_REPO}:latest -f Dockerfile .
}

assert_args_are_valid(){
    # Asserts arguments passed in to this script and environment variables required by this script are valid
    if [[ -z "$1" ]]; then
        echo "ERROR: An environment file argument is required by this script." >&2
        echo "         usage: ./build.sh environments/example.env" >&2
        exit 1
    fi
}

assert_env_vars_valid(){
    # Asserts environment variables required by this script are valid

    if [[ -z ${NGINX_CONFIG_FILE_NAME+x} ]]; then
        echo "ERROR: NGINX_CONFIG_FILE_NAME not set or empty but is required by this script. Ensure it is included in the .env file or exported prior to running this script." >&2
        echo "         export example:" >&2
        echo "         $ export NGINX_CONFIG_FILE_NAME='example.nginx.conf'" >&2
        exit 1
    fi
    if [[ -z ${CERTBOT_CONFIG_FILE_NAME+x} ]]; then
        echo "ERROR: CERTBOT_CONFIG_FILE_NAME not set or empty but is required by this script. Ensure it is included in the .env file or exported prior to running this script." >&2
        echo "         export example:" >&2
        echo "         $ export CERTBOT_CONFIG_FILE_NAME='example.certbot.ini'" >&2
        exit 1
    fi
    if [[ -z ${IMAGE_REPO+x} ]]; then
        echo "ERROR: IMAGE_REPO not set or empty but is required by this script. Ensure it is included in the .env file or exported prior to running this script." >&2
        echo "         export example:" >&2
        echo "         $ export IMAGE_REPO='nginx/proxy'" >&2
        exit 1
    fi
}

prepare_artifacts() {
    # Merges static artifacts with environment config files into a temporary artifacts folder
    # Sets the tmp_artifacts_dir variable

    # Create temporary directory
    tmp_artifacts_dir=$(mktemp -d "artifacts.XXXXXXXXXXXXXXXX" -p .)
    trap 'rm -rf "$tmp_artifacts_dir"' EXIT

    cp -r artifacts/* "$tmp_artifacts_dir/"
    mkdir -p ${tmp_artifacts_dir}/etc/nginx/conf.d/
    cp "environments/${NGINX_CONFIG_FILE_NAME}" "${tmp_artifacts_dir}/etc/nginx/conf.d/${NGINX_CONFIG_FILE_NAME}"
    mkdir -p ${tmp_artifacts_dir}/opt/certbot-config/
    cp "environments/${CERTBOT_CONFIG_FILE_NAME}" "${tmp_artifacts_dir}/opt/certbot-config/${CERTBOT_CONFIG_FILE_NAME}"
}

main "$@"