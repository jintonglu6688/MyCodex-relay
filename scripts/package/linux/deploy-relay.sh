#!/usr/bin/env sh
set -eu

umask 077

COMMAND="${1:-}"
if [ -n "$COMMAND" ]; then
  shift
fi

DOMAIN=""
EMAIL=""
TENANT_NAME="Production"
LISTEN_PORT="38443"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
SOURCE_BINARY="$SCRIPT_DIR/mycodex-relay"
INSTALL_DIR="/opt/mycodex-relay"
CONFIG_DIR="/etc/mycodex-relay"
STATE_DIR="/var/lib/mycodex-relay"
CONFIG_PATH="$CONFIG_DIR/relay-config.json"
SERVICE_NAME="mycodex-relay"
SERVICE_USER="mycodex-relay"

usage() {
  cat <<'EOF'
Usage:
  sudo ./deploy-relay.sh install --domain relay.example.com --email admin@example.com [--tenant-name Production] [--binary ./mycodex-relay]
  sudo ./deploy-relay.sh upgrade [--binary ./mycodex-relay]
  sudo ./deploy-relay.sh info
EOF
}

fail() {
  echo "Error: $*" >&2
  exit 1
}

require_root() {
  [ "$(id -u)" -eq 0 ] || fail "run this script with sudo"
}

validate_domain() {
  case "$DOMAIN" in
    ""|*[!A-Za-z0-9.-]*) fail "invalid domain: $DOMAIN" ;;
  esac
}

parse_options() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --domain)
        [ "$#" -ge 2 ] || fail "--domain requires a value"
        DOMAIN="$2"
        shift 2
        ;;
      --email)
        [ "$#" -ge 2 ] || fail "--email requires a value"
        EMAIL="$2"
        shift 2
        ;;
      --tenant-name)
        [ "$#" -ge 2 ] || fail "--tenant-name requires a value"
        TENANT_NAME="$2"
        shift 2
        ;;
      --listen-port)
        [ "$#" -ge 2 ] || fail "--listen-port requires a value"
        LISTEN_PORT="$2"
        shift 2
        ;;
      --binary)
        [ "$#" -ge 2 ] || fail "--binary requires a value"
        SOURCE_BINARY="$2"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        fail "unknown option: $1"
        ;;
    esac
  done
}

install_binary() {
  [ -f "$SOURCE_BINARY" ] || fail "Relay binary not found: $SOURCE_BINARY"
  install -d -m 0755 "$INSTALL_DIR"
  install -m 0755 "$SOURCE_BINARY" "$INSTALL_DIR/mycodex-relay"
}

write_service() {
  cat >"/etc/systemd/system/$SERVICE_NAME.service" <<EOF
[Unit]
Description=MyCodex Relay
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$STATE_DIR
ExecStart=$INSTALL_DIR/mycodex-relay serve --config $CONFIG_PATH
Restart=on-failure
RestartSec=5s
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ProtectKernelLogs=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
ReadWritePaths=$STATE_DIR
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
}

write_nginx_site() {
  if [ -e "/etc/nginx/sites-available/$SERVICE_NAME.conf" ] &&
    ! grep -Fq "Managed by MyCodex Relay deploy-relay.sh" "/etc/nginx/sites-available/$SERVICE_NAME.conf"; then
    fail "an existing Nginx site would be overwritten: /etc/nginx/sites-available/$SERVICE_NAME.conf"
  fi
  cat >"/etc/nginx/sites-available/$SERVICE_NAME.conf" <<EOF
# Managed by MyCodex Relay deploy-relay.sh
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;

    client_max_body_size 12m;

    location / {
        proxy_pass http://127.0.0.1:$LISTEN_PORT;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 180s;
        proxy_send_timeout 180s;
        proxy_buffering off;
    }
}
EOF
  ln -sfn "/etc/nginx/sites-available/$SERVICE_NAME.conf" "/etc/nginx/sites-enabled/$SERVICE_NAME.conf"
  nginx -t
  systemctl enable --now nginx
  systemctl reload nginx
}

show_info() {
  [ -x "$INSTALL_DIR/mycodex-relay" ] || fail "Relay is not installed"
  [ -f "$CONFIG_PATH" ] || fail "Relay configuration was not found"
  "$INSTALL_DIR/mycodex-relay" info --config "$CONFIG_PATH" --json
}

install_relay() {
  [ -n "$DOMAIN" ] || fail "--domain is required"
  [ -n "$EMAIL" ] || fail "--email is required"
  validate_domain
  case "$LISTEN_PORT" in
    *[!0-9]*|"") fail "invalid listen port: $LISTEN_PORT" ;;
  esac
  [ "$LISTEN_PORT" -ge 1 ] && [ "$LISTEN_PORT" -le 65535 ] || fail "invalid listen port: $LISTEN_PORT"
  command -v apt-get >/dev/null 2>&1 || fail "automatic deployment currently supports Ubuntu and Debian"

  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y nginx certbot python3-certbot-nginx curl ca-certificates

  if ! id "$SERVICE_USER" >/dev/null 2>&1; then
    useradd --system --home "$STATE_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
  fi
  install -d -m 0750 -o root -g "$SERVICE_USER" "$CONFIG_DIR"
  install -d -m 0700 -o "$SERVICE_USER" -g "$SERVICE_USER" "$STATE_DIR"
  install_binary

  if [ ! -f "$CONFIG_PATH" ]; then
    "$INSTALL_DIR/mycodex-relay" local init \
      --config "$CONFIG_PATH" \
      --state "$STATE_DIR/relay-state.db" \
      --listen-host 127.0.0.1 \
      --listen-port "$LISTEN_PORT" \
      --public-host "$DOMAIN" \
      --public-port 443 \
      --public-tls \
      --json >/dev/null
  else
    EXISTING_INFO="$("$INSTALL_DIR/mycodex-relay" info --config "$CONFIG_PATH" --json)"
    printf '%s\n' "$EXISTING_INFO" | grep -F "\"publicHost\": \"$DOMAIN\"" >/dev/null ||
      fail "existing Relay configuration uses a different public host"
    printf '%s\n' "$EXISTING_INFO" | grep -F '"tlsRequired": true' >/dev/null ||
      fail "existing Relay configuration does not declare public TLS"
  fi

  CONNECTION_INFO="$("$INSTALL_DIR/mycodex-relay" info \
    --config "$CONFIG_PATH" \
    --ensure-tenant \
    --tenant-name "$TENANT_NAME" \
    --json)"
  chown -R "$SERVICE_USER:$SERVICE_USER" "$STATE_DIR"
  chown root:"$SERVICE_USER" "$CONFIG_PATH"
  chmod 0640 "$CONFIG_PATH"

  write_service
  systemctl enable --now "$SERVICE_NAME"
  systemctl restart "$SERVICE_NAME"
  write_nginx_site
  certbot --nginx \
    --domain "$DOMAIN" \
    --email "$EMAIL" \
    --agree-tos \
    --non-interactive \
    --redirect \
    --keep-until-expiring

  curl --fail --silent --show-error "https://$DOMAIN/health" >/dev/null
  curl --fail --silent --show-error "https://$DOMAIN/.well-known/mycodex-relay" >/dev/null

  echo "MyCodex Relay deployment succeeded."
  echo "Save the following JSON now. A newly created tenant secret is shown only once:"
  printf '%s\n' "$CONNECTION_INFO"
}

upgrade_relay() {
  [ -f "$CONFIG_PATH" ] || fail "Relay is not installed"
  install_binary
  systemctl restart "$SERVICE_NAME"
  systemctl is-active --quiet "$SERVICE_NAME" || fail "Relay service did not start"
  show_info
}

parse_options "$@"
case "$COMMAND" in
  install)
    require_root
    install_relay
    ;;
  upgrade)
    require_root
    upgrade_relay
    ;;
  info)
    require_root
    show_info
    ;;
  -h|--help|"")
    usage
    ;;
  *)
    fail "unknown command: $COMMAND"
    ;;
esac
