#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# Lightway WebSocket Server Auto Setup
#
# Deploys nginx or caddy as TLS/WebSocket reverse proxy for lightway-server.
# lightway-server handles WebSocket natively (--websocket flag).
#
# Usage:
#   sudo bash setup.sh --proxy nginx --domain vpn.example.com [options]
#   sudo bash setup.sh --proxy caddy --domain vpn.example.com [options]
#
# Options:
#   --proxy   nginx|caddy        Reverse proxy to use (required)
#   --domain  DOMAIN             Domain name for TLS cert (required)
#   --ws-path PATH               WebSocket path (default: /ws)
#   --lw-port PORT               lightway-server listen port (default: 9443)
#   --lw-bin  PATH               Path to lightway-server binary
#   --lw-config PATH             Path to lightway-server config yaml
#   --site    PATH               Path to static site directory for camouflage
#   --help                       Show this help
# ============================================================================

PROXY="nginx"
DOMAIN="hk1.03178.net"
WS_PATH="/api"
LW_PORT=9443
LW_BIN="lightway-server"
LW_CONFIG="server_config.yaml"
SITE_DIR="/var/www/html"

usage() {
    head -n 20 "$0" | grep -E '^#' | sed 's/^# //'
    exit 0
}

log() { echo -e "\033[1;32m[+]\033[0m $*"; }
warn() { echo -e "\033[1;33m[!]\033[0m $*"; }
err() { echo -e "\033[1;31m[x]\033[0m $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --proxy)      PROXY="$2"; shift 2 ;;
        --domain)     DOMAIN="$2"; shift 2 ;;
        --ws-path)    WS_PATH="$2"; shift 2 ;;
        --lw-port)    LW_PORT="$2"; shift 2 ;;
        --lw-bin)     LW_BIN="$2"; shift 2 ;;
        --lw-config)  LW_CONFIG="$2"; shift 2 ;;
        --site)       SITE_DIR="$2"; shift 2 ;;
        --help|-h)    usage ;;
        *)            err "Unknown option: $1" ;;
    esac
done

[[ -z "$PROXY" ]] && err "Missing --proxy (nginx or caddy)"
[[ -z "$DOMAIN" ]] && err "Missing --domain"
[[ "$PROXY" != "nginx" && "$PROXY" != "caddy" ]] && err "--proxy must be nginx or caddy"
[[ $(id -u) -ne 0 ]] && err "Please run as root (sudo)"

# ---- Optional: setup lightway-server systemd service ----

setup_lightway_server() {
    if [[ -z "$LW_BIN" || -z "$LW_CONFIG" ]]; then
        warn "Skipping lightway-server service setup (use --lw-bin and --lw-config to enable)"
        warn "Make sure lightway-server is running with: --websocket --ws-path $WS_PATH --bind-address 0.0.0.0:$LW_PORT"
        return
    fi

    [[ ! -f "$LW_BIN" ]] && err "lightway-server binary not found: $LW_BIN"
    [[ ! -f "$LW_CONFIG" ]] && err "lightway-server config not found: $LW_CONFIG"

    local lw_dir="/etc/lightway"
    mkdir -p "$lw_dir"

    log "Installing lightway-server files to ${lw_dir}..."
    cp "$LW_BIN" "$lw_dir/lightway-server"
    chmod +x "$lw_dir/lightway-server"
    cp "$LW_CONFIG" "$lw_dir/server_config.yaml"

    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local start_script=""
    for candidate in "$script_dir/server_start.sh" "$script_dir/../samples/server_start.sh"; do
        if [[ -f "$candidate" ]]; then
            start_script="$candidate"
            break
        fi
    done
    [[ -z "$start_script" ]] && err "server_start.sh not found (checked ws/ and samples/)"

    cp "$start_script" "$lw_dir/server_start.sh"
    chmod +x "$lw_dir/server_start.sh"

    log "Installing dependencies for server_start.sh (yq, jq, iptables)..."
    apt-get update -qq
    apt-get install -y -qq jq iptables iproute2 procps
    if ! command -v yq &>/dev/null; then
        log "Installing yq..."
        local arch
        arch=$(dpkg --print-architecture 2>/dev/null || echo "amd64")
        curl -fsSL "https://github.com/mikefarah/yq/releases/latest/download/yq_linux_${arch}" -o /usr/local/bin/yq
        chmod +x /usr/local/bin/yq
    fi

    log "Creating lightway-server systemd service..."
    cat > /etc/systemd/system/lightway-server.service <<EOF
[Unit]
Description=Lightway VPN Server (WebSocket)
After=network.target

[Service]
Type=simple
WorkingDirectory=${lw_dir}
ExecStart=/bin/bash ${lw_dir}/server_start.sh ${lw_dir}/server_config.yaml
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now lightway-server
    log "lightway-server service started"
}

# ---- Setup nginx ----

setup_nginx() {
    log "Setting up nginx..."

    if ! command -v nginx &>/dev/null; then
        log "Installing nginx..."
        apt-get update -qq && apt-get install -y -qq nginx
    fi

    if ! command -v certbot &>/dev/null; then
        log "Installing certbot..."
        apt-get install -y -qq certbot python3-certbot-nginx
    fi

    local site="${SITE_DIR:-/var/www/html}"
    mkdir -p "$site"
    if [[ ! -f "$site/index.html" ]]; then
        echo "<html><body><h1>Welcome</h1></body></html>" > "$site/index.html"
    fi

    local conf="/etc/nginx/sites-available/lightway-ws"
    ln -sf "$conf" /etc/nginx/sites-enabled/lightway-ws
    rm -f /etc/nginx/sites-enabled/default

    if [[ ! -d "/etc/letsencrypt/live/${DOMAIN}" ]]; then
        log "Writing temporary HTTP-only config for certificate provisioning..."
        cat > "$conf" <<NGINX_EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};
    root ${site};
    location / {
        try_files \$uri \$uri/ =404;
    }
}
NGINX_EOF
        nginx -t && systemctl reload nginx

        log "Obtaining TLS certificate via certbot..."
        certbot certonly --webroot -w "$site" -d "$DOMAIN" --non-interactive --agree-tos --register-unsafely-without-email
    else
        log "TLS certificate already exists for $DOMAIN"
    fi

    log "Writing full HTTPS + WebSocket config..."
    cat > "$conf" <<NGINX_EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};

    location /.well-known/acme-challenge/ {
        root ${site};
    }
    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name ${DOMAIN};

    ssl_certificate     /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache   shared:SSL:10m;
    ssl_session_timeout 1d;

    root ${site};
    index index.html;

    location / {
        try_files \$uri \$uri/ =404;
    }

    location ${WS_PATH} {
        proxy_pass http://127.0.0.1:${LW_PORT};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }
}
NGINX_EOF

    nginx -t && systemctl reload nginx
    log "nginx configured and reloaded"
}

# ---- Setup caddy ----

setup_caddy() {
    log "Setting up caddy..."

    if ! command -v caddy &>/dev/null; then
        log "Installing caddy..."
        apt-get update -qq && apt-get install -y -qq debian-keyring debian-archive-keyring apt-transport-https curl
        curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
        curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
        apt-get update -qq && apt-get install -y -qq caddy
    fi

    local site="${SITE_DIR:-/var/www/html}"
    mkdir -p "$site"
    if [[ ! -f "$site/index.html" ]]; then
        echo "<html><body><h1>Welcome</h1></body></html>" > "$site/index.html"
    fi

    cat > /etc/caddy/Caddyfile <<CADDY_EOF
${DOMAIN} {
    root * ${site}
    file_server

    route ${WS_PATH} {
        @ws_upgrade {
            header Connection *Upgrade*
            header Upgrade websocket
        }
        reverse_proxy @ws_upgrade 127.0.0.1:${LW_PORT}
        respond "Not Found" 404
    }
}
CADDY_EOF

    systemctl reload caddy || systemctl restart caddy
    log "caddy configured (TLS auto-managed via Let's Encrypt)"
}

# ---- Main ----

log "Lightway WebSocket Server Setup"
log "  Proxy:       $PROXY"
log "  Domain:      $DOMAIN"
log "  WS Path:     $WS_PATH"
log "  LW Port:     $LW_PORT"
echo

setup_lightway_server

case "$PROXY" in
    nginx) setup_nginx ;;
    caddy) setup_caddy ;;
esac

echo
log "========================================="
log " Deployment complete!"
log "========================================="
log ""
log "Server config (server_config.yaml):"
log "  mode: tcp"
log "  websocket: true"
log "  ws_path: \"${WS_PATH}\""
log "  bind_address: \"0.0.0.0:${LW_PORT}\""
log ""
log "Client config (client_config.yaml):"
log "  server: \"${DOMAIN}:443\""
log "  mode: tcp"
log "  websocket: true"
log "  ws_path: \"${WS_PATH}\""
log "  ws_host: \"${DOMAIN}\""
log ""
log "Test WebSocket connectivity:"
log "  curl -i -N -H 'Connection: Upgrade' -H 'Upgrade: websocket' \\"
log "    -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGVzdA==' \\"
log "    https://${DOMAIN}${WS_PATH}"
