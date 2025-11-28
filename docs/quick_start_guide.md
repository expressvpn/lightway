# Quick Start Guide

This guide will help you quickly set up a Lightway VPN server and client using the nightly builds.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Setting up the Server](#setting-up-the-server)
- [Setting up the Client](#setting-up-the-client)

## Prerequisites

### Server Requirements

- Nix user
  - use quick start shell
  - `nix develop github:expressvpn/lightway#quick-start`
- None Nix user
  - Linux system (x86_64, arm64, or riscv64)
  - Root or sudo access
  - The following packages:
    - `jq`, `yq` (for parsing server and client config.yaml files)
    - `apache2-utils` (htpasswd for user authentication)
    - `iproute2`
    - `iptables`
  - Install dependencies on Debian/Ubuntu:
```bash
sudo apt-get update
sudo apt-get install jq yq apache2-utils iproutes2 iptables
```

### Client Requirements

- Linux, macOS, or Windows system
- Root or sudo access (required for tunnel device management on Linux/macOS)
- On Windows, [Wintun](https://www.wintun.net/)

## Setting up the Server

### 1. Download Server Binary

Download the server binary from the [nightly releases page](https://github.com/expressvpn/lightway/releases/tag/lightway-nightly), or:

```bash
ARCH=$(uname -m); [[ "$ARCH" == "arm64" ]] && ARCH="aarch64"
curl -fL "https://github.com/expressvpn/lightway/releases/download/lightway-nightly/lightway-server-${ARCH}-unknown-linux-gnu" -o lightway-server
chmod +x lightway-server
```

### 2. Download the Setup Script
- Nix user
  - The script is also included in the quick-start shell, you do not need to download it.

- None Nix user
  - Download latest script from repository
```bash
curl -L -o server_start.sh https://raw.githubusercontent.com/expressvpn/lightway/main/samples/server_start.sh
chmod +x server_start.sh
```

### 3. Create User Database

Create a password file for user authentication using `htpasswd`:

```bash
# Replace 'myuser' with your desired username
htpasswd -B -c lwpasswd myuser
```

Enter the password when prompted. This creates a `lwpasswd` file with your username and securely hashed password.

To add additional users to the database, omit the `-c` flag:
```bash
# Add another user
htpasswd -B lwpasswd anotheruser
```

### 4. Generate Certificates

You need TLS certificates for the server. For testing, you can generate self-signed certificates:

```bash
# Create a directory for certificates
mkdir certs && cd certs

# Generate CA key and certificate
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.crt
```

You'll be prompted for details (country, state, organization, etc.). Fill them in as appropriate.

```bash
# Generate server key and certificate
openssl genrsa -out server.key 4096
openssl req -new -key server.key -out server.csr
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -sha256
```

### 5. Create Server Configuration

Use the example config from the repository:

```bash
curl -L -o server_config.yaml https://raw.githubusercontent.com/expressvpn/lightway/main/tests/server/server_config.yaml
```

Edit the config to update the database (`user_db`) and certificate paths (`server_cert` and `server_key`)

### 6. Start the Server

Use the provided setup script to start the server:

- Nix user
```bash
sudo server_start server_config.yaml
```

- None Nix user
```bash
sudo ./server_start.sh server_config.yaml
```

- Create and configure the TUN interface
- Set up IP forwarding
- Configure NAT/SNAT rules
- Start the Lightway server

The server will now listen on port 27690 (or the port you configured).

## Setting up the Client

### 1. Download Client Binary

Download the client for your platform from the [nightly releases page](https://github.com/expressvpn/lightway/releases/tag/lightway-nightly).

Available platforms:
- **Linux**: x86_64, aarch64, riscv64
- **macOS**: x86_64 (Intel), aarch64 (Apple Silicon)
- **Windows**: x86_64, aarch64

After downloading, make it executable (Linux/macOS):
```bash
chmod +x lightway-client
```

On Windows, you will need to download [Wintun](https://www.wintun.net/) and place `wintun.dll` in the same directory as `lightway-client`.

### 2. Copy CA Certificate

Copy the `ca.crt` file from your server to the client machine.

### 3. Create Client Configuration

Use the example config from the repository:

```bash
curl -L -o client_config.yaml https://raw.githubusercontent.com/expressvpn/lightway/main/tests/client/client_config.yaml
```

Edit the config to update `server`, `ca_cert`, `user`, and `password` fields.

### 4. Start the Client

Run the client to establish a VPN connection to the server:

- Nix user
```bash
sudo nix run github:expressvpn/lightway#lightway-client -- --config-file client_config.yaml
```

- None Nix user
```bash
sudo ./lightway-client --config-file client_config.yaml
```
