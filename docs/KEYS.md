# LogHawk TLS Key and Certificate Files

This project uses OpenSSL to generate a small private certificate authority (CA), one server certificate for the central rsyslog collector, and one client certificate per agent for mutual TLS (mTLS).

The scripts that create these files are:

- `central/generate-certs.sh`
- `central/generate-client-cert.sh`

This document explains what each generated file is for, what the abbreviations mean, and which files belong on the server vs. the agents.

## Quick glossary

- `CA`: Certificate Authority. The private authority that signs the server and client certificates.
- `key`: A private key. Secret material. Never distribute it unless that machine must actually use it.
- `cert`: A certificate. Public-facing identity document signed by the CA.
- `CSR`: Certificate Signing Request. A request file created from a private key and sent to a CA for signing.
- `cnf`: OpenSSL config file format. Short for "configuration".
- `ext`: Extensions file. In this repo it is a small OpenSSL config file containing certificate extensions such as `extendedKeyUsage` and `subjectAltName`.
- `CN`: Common Name. The subject name placed into the certificate, like `log-server.example.com` or `web-01`.
- `PEM`: Privacy-Enhanced Mail format. In practice, a base64-encoded text file with headers like `-----BEGIN CERTIFICATE-----`.
- `mTLS`: Mutual TLS. Both sides authenticate with certificates: the server proves its identity to the client, and the client proves its identity to the server.

## File-by-file explanation

### CA files

#### `CA_KEY="${OUT_DIR}/ca/ca-key.pem"`

The CA private key.

- Purpose: This is the secret signing key for the private LogHawk certificate authority.
- Used for: Signing the server certificate and every client certificate.
- Keep it where: Only on the machine and in the directory where you generate certificates.
- Do not copy it to: Agents, the deployed rsyslog cert directory, or any host that does not need to issue new certificates.
- Sensitivity: Highest. If this key is leaked, someone can mint trusted certificates for your logging environment.

#### `CA_CERT="${OUT_DIR}/ca/logging-ca.pem"`

The CA certificate.

- Purpose: This is the public certificate for the private CA.
- Used for: Letting rsyslog verify that a server certificate or client certificate was signed by the trusted LogHawk CA.
- Copy it to: The central server and every agent.
- Safe to share: Yes, within the environment. This is the trust anchor, not the signing secret.

In practice:

- Agents use this CA cert to verify the central server certificate.
- The central server uses this CA cert to verify client certificates from agents.

### Server files

These identify the central rsyslog collector.

#### `SERVER_KEY="${OUT_DIR}/server/server-key.pem"`

The server private key.

- Purpose: Private key for the central collector's identity.
- Used for: Proving possession of the server certificate during the TLS handshake.
- Deploy to: The central server only.
- Do not copy to: Agents or any other host.

#### `SERVER_CSR="${OUT_DIR}/server/server.csr"`

The server certificate signing request.

- Purpose: Intermediate request generated from `server-key.pem`.
- Used for: Asking the CA to create `server-cert.pem`.
- Contains: The requested subject, including the server `CN`, and it is paired with the server private key.
- Operational note: This is mainly a build artifact. It is useful during certificate generation but is not usually deployed to rsyslog hosts.

#### `SERVER_CERT="${OUT_DIR}/server/server-cert.pem"`

The server certificate.

- Purpose: Public certificate presented by the central collector to agents.
- Used for: Server authentication during TLS.
- Signed by: `logging-ca.pem` using `ca-key.pem`.
- Deploy to: The central server alongside `server-key.pem`.

In this repo, the server certificate is issued with `extendedKeyUsage=serverAuth`, which marks it as a server certificate.

#### `SERVER_EXT="${OUT_DIR}/server/server-ext.cnf"`

The server certificate extensions file.

- Purpose: Small OpenSSL configuration file used when signing the server CSR.
- Used for: Telling OpenSSL which certificate extensions to add.
- In this repo it contains:
  - `subjectAltName=DNS:<server-name>` and optionally `IP:<server-address>`
  - `extendedKeyUsage=serverAuth`
- Why it matters: Modern TLS clients validate the SAN (`subjectAltName`) when checking the hostname or IP address they connected to.

This file is not a key and not a certificate. It is just input to OpenSSL during certificate creation.

### Client files

Each agent gets its own client certificate directory under `central/certs/clients/<client-name>/`.

#### `client_key="${client_dir}/client-key.pem"`

The client private key.

- Purpose: Private key for a specific agent's identity.
- Used for: Proving that the agent owns its client certificate when connecting to the central collector.
- Deploy to: Exactly one agent host, the one named by that client certificate.
- Do not share: Each agent should have its own unique key.

#### `client_csr="${client_dir}/client.csr"`

The client certificate signing request.

- Purpose: Intermediate request generated from `client-key.pem`.
- Used for: Asking the CA to create `client-cert.pem`.
- Operational note: Like the server CSR, this is mainly a generation artifact and usually not deployed.

#### `client_cert="${client_dir}/client-cert.pem"`

The client certificate.

- Purpose: Public certificate presented by an agent to the central collector.
- Used for: Client authentication during mTLS.
- Signed by: `logging-ca.pem` using `ca-key.pem`.
- Deploy to: The matching agent host, alongside that agent's `client-key.pem`.

In this repo, the client certificate is issued with `extendedKeyUsage=clientAuth`, which marks it as a client certificate.

#### `client_ext="${client_dir}/client-ext.cnf"`

The client certificate extensions file.

- Purpose: Small OpenSSL configuration file used when signing the client CSR.
- Used for: Adding certificate extensions to the client certificate.
- In this repo it contains:
  - `extendedKeyUsage=clientAuth`

Like `server-ext.cnf`, this is not a secret and not a deployable cert file. It is just part of the certificate-generation process.

## What goes where

### Keep only in the certificate generation area

- `ca-key.pem`
- `server.csr`
- `client.csr`
- `server-ext.cnf`
- `client-ext.cnf`

### Deploy to the central server

- `logging-ca.pem`
- `server-cert.pem`
- `server-key.pem`

### Deploy to each agent

- `logging-ca.pem`
- That agent's `client-cert.pem`
- That agent's `client-key.pem`

## How the chain works

The trust model is simple:

1. `ca-key.pem` signs `logging-ca.pem` as the root CA certificate.
2. `ca-key.pem` signs `server.csr` and produces `server-cert.pem`.
3. `ca-key.pem` signs each `client.csr` and produces a `client-cert.pem`.
4. Both sides trust `logging-ca.pem`.
5. During mTLS:
   - The agent verifies the server certificate against `logging-ca.pem`.
   - The central server verifies the client certificate against `logging-ca.pem`.

## Common abbreviation questions

### What is `ca`?

`ca` stands for `certificate authority`.

It is the entity that signs certificates and acts as the root of trust. In LogHawk, that CA is private and local to your deployment. It is not a public internet CA like Let's Encrypt.

### What does `cnf` mean?

`cnf` means `configuration`.

OpenSSL commonly uses `.cnf` files for configuration input. In this repo, the `*-ext.cnf` files are tiny config files that tell OpenSSL which extensions to add while signing certificates.

### What is `ext` short for?

`ext` is short for `extensions`.

It refers to X.509 certificate extensions such as:

- `extendedKeyUsage`
- `subjectAltName`

### What is `csr`?

`csr` means `certificate signing request`.

It is the request created from a private key before the CA issues the final certificate.

### What is the difference between a key and a cert?

- A `key` is private and must be protected.
- A `cert` is public and is meant to be presented to peers.

If you remember only one thing: never distribute the CA private key or reuse client private keys across hosts.

## Practical summary

If you are just trying to understand the minimum:

- `ca-key.pem`: the master signing secret
- `logging-ca.pem`: the public CA certificate everyone trusts
- `server-key.pem`: the log server's secret key
- `server-cert.pem`: the log server's public certificate
- `client-key.pem`: one agent's secret key
- `client-cert.pem`: one agent's public certificate
- `*.csr`: temporary signing requests
- `*-ext.cnf`: OpenSSL config files that define certificate extensions

<br>
