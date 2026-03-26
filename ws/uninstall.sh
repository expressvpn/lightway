#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# Lightway WebSocket Server Uninstall
#
# Removes lightway-server service, reverse proxy config, and related files.
#
# Usage:
#   sudo bash uninstall.sh [options]
#
# Options:
#   --purge       Also remove TLS certificates and uninstall nginx/caddy packages
#   --keep-certs  Keep Let's Encrypt certificates (default)
#   --help        Show this help
# ============================================================================

PURGE=false

log() { echo -e "\033[1;32m[+]\033[0m $*"; }
warn() { echo -e "\033[1;33m[!]\033[0m $*"; }
err() { echo -e "\033[1;31m[x]\033[0m $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --purge)      PURGE=true; shift ;;
        --keep-certs) PURGE=false; shift ;;
        --help|-h)    head -n 15 "$0" | grep -E '^#' | sed 's/^# //'; exit 0 ;;
        *)            err "Unknown option: $1" ;;
    esac
done

[[ $(id -u) -ne 0 ]] && err "Please run as root (sudo)"

log "Lightway WebSocket Server Uninstall"
echo

# ---- Stop and remove lightway-server ----

if systemctl list-unit-files lightway-server.service &>/dev/null; then
    log "Stopping lightway-server service..."
    systemctl stop lightway-server 2>/dev/null || true
    systemctl disable lightway-server 2>/dev/null || true
    rm -f /etc/systemd/system/lightway-server.service
    systemctl daemon-reload
    log "lightway-server service removed"
else
    warn "lightway-server service not found, skipping"
fi

# ---- Clean up TUN interface and iptables rules ----

if [[ -d /etc/lightway ]] && [[ -f /etc/lightway/server_config.yaml ]]; then
    if command -v yq &>/dev/null; then
        tun_intf=$(yq -r '.tun_name' /etc/lightway/server_config.yaml 2>/dev/null || echo "")
        tun_ip_subnet=$(yq -r '.ip_pool' /etc/lightway/server_config.yaml 2>/dev/null || echo "")

        if [[ -n "$tun_intf" ]] && ip link show "$tun_intf" &>/dev/null; then
            log "Removing TUN interface: $tun_intf"
            ip link set dev "$tun_intf" down 2>/dev/null || true
            ip tuntap del mode tun dev "$tun_intf" 2>/dev/null || true
        fi

        if [[ -n "$tun_ip_subnet" ]]; then
            wandev=$(ip --json route get 8.8.8.8 2>/dev/null | jq -r '.[0].dev' 2>/dev/null || echo "")
            basenet=$(ip --json addr show "$wandev" 2>/dev/null | jq -r '.[0].addr_info[0].local' 2>/dev/null || echo "")
            if [[ -n "$wandev" && -n "$basenet" ]]; then
                log "Removing iptables SNAT rule..."
                iptables -t nat -D POSTROUTING -s "$tun_ip_subnet" -o "$wandev" -j SNAT --to "$basenet" 2>/dev/null || true
            fi
        fi
    else
        warn "yq not found, skipping TUN/iptables cleanup (do it manually if needed)"
    fi
fi

# ---- Remove lightway files ----

if [[ -d /etc/lightway ]]; then
    log "Removing /etc/lightway/"
    rm -rf /etc/lightway
fi

# ---- Remove nginx config ----

if [[ -f /etc/nginx/sites-enabled/lightway-ws ]] || [[ -f /etc/nginx/sites-available/lightway-ws ]]; then
    log "Removing nginx lightway-ws config..."
    rm -f /etc/nginx/sites-enabled/lightway-ws
    rm -f /etc/nginx/sites-available/lightway-ws
    if command -v nginx &>/dev/null; then
        nginx -t 2>/dev/null && systemctl reload nginx 2>/dev/null || true
    fi
    log "nginx config removed"
fi

# ---- Remove caddy config ----

if [[ -f /etc/caddy/Caddyfile ]]; then
    if grep -q 'lightway\|reverse_proxy.*127.0.0.1' /etc/caddy/Caddyfile 2>/dev/null; then
        log "Removing Caddy config..."
        rm -f /etc/caddy/Caddyfile
        systemctl reload caddy 2>/dev/null || true
        log "Caddy config removed"
    fi
fi

# ---- Purge mode: remove packages and certs ----

if $PURGE; then
    log "Purge mode: removing packages and certificates..."

    if dpkg -l nginx &>/dev/null 2>&1; then
        log "Removing nginx..."
        apt-get purge -y -qq nginx nginx-common 2>/dev/null || true
    fi

    if dpkg -l caddy &>/dev/null 2>&1; then
        log "Removing caddy..."
        apt-get purge -y -qq caddy 2>/dev/null || true
        rm -f /etc/apt/sources.list.d/caddy-stable.list
        rm -f /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    fi

    if dpkg -l certbot &>/dev/null 2>&1; then
        log "Removing certbot..."
        apt-get purge -y -qq certbot python3-certbot-nginx 2>/dev/null || true
    fi

    if [[ -d /etc/letsencrypt ]]; then
        log "Removing Let's Encrypt certificates..."
        rm -rf /etc/letsencrypt
    fi

    apt-get autoremove -y -qq 2>/dev/null || true
else
    warn "TLS certificates kept (use --purge to also remove them)"
fi

echo
log "========================================="
log " Uninstall complete!"
log "========================================="
