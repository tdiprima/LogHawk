#!/usr/bin/env bash
# generate-certs.sh
# Generate a small private CA plus server/client certificates for rsyslog mTLS.
#
# Usage:
#   ./generate-certs.sh --server-name log-server.example.com \
#       --server-address 10.0.0.10 \
#       --client-name web-01 \
#       --client-name db-01

set -euo pipefail

OUT_DIR="${PWD}/central/certs"
SERVER_NAME=""
SERVER_ADDRESS=""
CLIENT_NAMES=()

usage() {
    cat <<EOF
Usage: $0 --server-name NAME [options]

Options:
  --server-name NAME      Required. DNS name placed in the server certificate.
  --server-address ADDR   Optional. Adds an IP SAN (virtualization) to the server certificate.
  --client-name NAME      Client certificate common name. Repeat for each agent.
  --out-dir PATH          Output directory (default: ${OUT_DIR})
  -h, --help              Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --server-name)
            SERVER_NAME="${2:-}"
            shift 2
            ;;
        --server-address)
            SERVER_ADDRESS="${2:-}"
            shift 2
            ;;
        --client-name)
            CLIENT_NAMES+=("${2:-}")
            shift 2
            ;;
        --out-dir)
            OUT_DIR="${2:-}"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --*)
            echo "ERROR: Unknown option: $1" >&2
            usage >&2
            exit 1
            ;;
        *)
            echo "ERROR: Unexpected argument: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

if [[ -z "${SERVER_NAME}" ]]; then
    echo "ERROR: --server-name is required." >&2
    exit 1
fi

if ! command -v openssl >/dev/null 2>&1; then
    echo "ERROR: openssl is required." >&2
    exit 2
fi

mkdir -p "${OUT_DIR}"/{ca,server,clients}
umask 077  # remove all permissions for group and others

CA_KEY="${OUT_DIR}/ca/ca-key.pem"
CA_CERT="${OUT_DIR}/ca/logging-ca.pem"

if [[ ! -f "${CA_KEY}" || ! -f "${CA_CERT}" ]]; then
    openssl genrsa -out "${CA_KEY}" 4096 >/dev/null 2>&1
    openssl req -x509 -new -nodes \
        -key "${CA_KEY}" \
        -sha256 \
        -days 3650 \
        -subj "/CN=log-hawk-ca" \
        -out "${CA_CERT}" >/dev/null 2>&1
fi

SERVER_KEY="${OUT_DIR}/server/server-key.pem"
SERVER_CSR="${OUT_DIR}/server/server.csr"
SERVER_CERT="${OUT_DIR}/server/server-cert.pem"
SERVER_EXT="${OUT_DIR}/server/server-ext.cnf"

{
    echo "subjectAltName=DNS:${SERVER_NAME}"
    if [[ -n "${SERVER_ADDRESS}" ]]; then
        echo "subjectAltName=DNS:${SERVER_NAME},IP:${SERVER_ADDRESS}"
    fi
    echo "extendedKeyUsage=serverAuth"
} > "${SERVER_EXT}"

openssl genrsa -out "${SERVER_KEY}" 4096 >/dev/null 2>&1
openssl req -new -key "${SERVER_KEY}" -subj "/CN=${SERVER_NAME}" -out "${SERVER_CSR}" >/dev/null 2>&1
openssl x509 -req \
    -in "${SERVER_CSR}" \
    -CA "${CA_CERT}" \
    -CAkey "${CA_KEY}" \
    -CAcreateserial \
    -out "${SERVER_CERT}" \
    -days 825 \
    -sha256 \
    -extfile "${SERVER_EXT}" >/dev/null 2>&1

for client_name in "${CLIENT_NAMES[@]}"; do
    client_dir="${OUT_DIR}/clients/${client_name}"
    mkdir -p "${client_dir}"

    client_key="${client_dir}/client-key.pem"
    client_csr="${client_dir}/client.csr"
    client_cert="${client_dir}/client-cert.pem"
    client_ext="${client_dir}/client-ext.cnf"

    printf 'extendedKeyUsage=clientAuth\n' > "${client_ext}"

    openssl genrsa -out "${client_key}" 4096 >/dev/null 2>&1
    openssl req -new -key "${client_key}" -subj "/CN=${client_name}" -out "${client_csr}" >/dev/null 2>&1
    openssl x509 -req \
        -in "${client_csr}" \
        -CA "${CA_CERT}" \
        -CAkey "${CA_KEY}" \
        -CAcreateserial \
        -out "${client_cert}" \
        -days 825 \
        -sha256 \
        -extfile "${client_ext}" >/dev/null 2>&1
done

cat <<EOF
Generated certificates under: ${OUT_DIR}

Collector files:
  CA:     ${CA_CERT}
  Cert:   ${SERVER_CERT}
  Key:    ${SERVER_KEY}

Agent files:
  Copy ${CA_CERT} to every host as the CA file.
  Copy one client cert/key pair from ${OUT_DIR}/clients/<hostname>/ to each host.
EOF
