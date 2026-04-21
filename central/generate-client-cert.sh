#!/usr/bin/env bash
# generate-client-cert.sh
# Generate a single additional client certificate signed by the existing CA.
#
# Usage:
#   ./generate-client-cert.sh --client-name web-02

set -euo pipefail

OUT_DIR="${PWD}/central/certs"
CLIENT_NAME=""
FORCE="false"

usage() {
    cat <<EOF
Usage: $0 --client-name NAME [options]

Options:
  --client-name NAME   Required. Client certificate common name and directory.
  --out-dir PATH       Certificate output directory (default: ${OUT_DIR})
  --force              Overwrite an existing client certificate directory.
  -h, --help           Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --client-name)
            CLIENT_NAME="${2:-}"
            shift 2
            ;;
        --out-dir)
            OUT_DIR="${2:-}"
            shift 2
            ;;
        --force)
            FORCE="true"
            shift
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

if [[ -z "${CLIENT_NAME}" ]]; then
    echo "ERROR: --client-name is required." >&2
    usage >&2
    exit 1
fi

if ! command -v openssl >/dev/null 2>&1; then
    echo "ERROR: openssl is required." >&2
    exit 2
fi

umask 077

CA_KEY="${OUT_DIR}/ca/ca-key.pem"
CA_CERT="${OUT_DIR}/ca/logging-ca.pem"
CLIENT_DIR="${OUT_DIR}/clients/${CLIENT_NAME}"
CLIENT_KEY="${CLIENT_DIR}/client-key.pem"
CLIENT_CSR="${CLIENT_DIR}/client.csr"
CLIENT_CERT="${CLIENT_DIR}/client-cert.pem"
CLIENT_EXT="${CLIENT_DIR}/client-ext.cnf"

for path in "${CA_KEY}" "${CA_CERT}"; do
    if [[ ! -f "${path}" ]]; then
        echo "ERROR: Missing CA file: ${path}" >&2
        echo "       Run ./central/generate-certs.sh first to create the CA." >&2
        exit 3
    fi
done

if [[ -e "${CLIENT_DIR}" && "${FORCE}" != "true" ]]; then
    echo "ERROR: Client directory already exists: ${CLIENT_DIR}" >&2
    echo "       Re-run with --force to replace this client's certificate." >&2
    exit 4
fi

mkdir -p "${CLIENT_DIR}"

printf 'extendedKeyUsage=clientAuth\n' > "${CLIENT_EXT}"

openssl genrsa -out "${CLIENT_KEY}" 4096 2>&1
openssl req -new -key "${CLIENT_KEY}" -subj "/CN=${CLIENT_NAME}" -out "${CLIENT_CSR}" 2>&1
openssl x509 -req \
    -in "${CLIENT_CSR}" \
    -CA "${CA_CERT}" \
    -CAkey "${CA_KEY}" \
    -CAcreateserial \
    -out "${CLIENT_CERT}" \
    -days 825 \
    -sha256 \
    -extfile "${CLIENT_EXT}" 2>&1

cat <<EOF
Generated client certificate under: ${CLIENT_DIR}

Copy these files to the target agent:
  CA:     ${CA_CERT}
  Cert:   ${CLIENT_CERT}
  Key:    ${CLIENT_KEY}
EOF
