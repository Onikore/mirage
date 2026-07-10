#!/bin/bash
set -e

echo "Starting Mirage installation..."

# Ensure root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

REPO_URL="https://github.com/Onikore/mirage.git"
SRC_DIR="/opt/mirage-src"
GO_VERSION="1.25.0"

# This script is meant to be run standalone (e.g. via `bash <(curl -sL ...)`),
# so it must fetch its own source -- it does not assume a pre-existing clone.
if [ ! -d "$SRC_DIR" ]; then
  echo "Cloning Mirage source..."
  if ! command -v git &> /dev/null; then
    apt-get update && apt-get install -y git
  fi
  git clone "$REPO_URL" "$SRC_DIR"
else
  echo "Updating existing Mirage source..."
  git -C "$SRC_DIR" pull --ff-only
fi
cd "$SRC_DIR"

# The distro's `golang` package is frequently older than what go.mod
# requires (go.mod currently needs 1.25+) -- install the exact upstream
# toolchain instead of trusting apt's version.
NEED_GO_INSTALL=1
if command -v go &> /dev/null; then
  CUR_GO=$(go version | awk '{print $3}' | sed 's/^go//')
  if [ "$(printf '%s\n' "$GO_VERSION" "$CUR_GO" | sort -V | head -n1)" = "$GO_VERSION" ]; then
    NEED_GO_INSTALL=0
  fi
fi
if [ "$NEED_GO_INSTALL" = "1" ]; then
  echo "Installing Go $GO_VERSION..."
  ARCH=$(uname -m)
  case "$ARCH" in
    x86_64) GOARCH=amd64 ;;
    aarch64) GOARCH=arm64 ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
  esac
  curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${GOARCH}.tar.gz" -o /tmp/go.tar.gz
  rm -rf /usr/local/go
  tar -C /usr/local -xzf /tmp/go.tar.gz
  rm -f /tmp/go.tar.gz
  ln -sf /usr/local/go/bin/go /usr/local/bin/go
  ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt
fi

echo "Building Mirage..."
CGO_ENABLED=0 go build -o mirage ./cmd/mirage
cp mirage /usr/local/bin/mirage

echo "Generating keys..."
mkdir -p /etc/mirage
OUTPUT=$(/usr/local/bin/mirage keygen)
PRIV=$(echo "$OUTPUT" | grep "server_priv:" | awk '{print $2}')
PUB=$(echo "$OUTPUT" | grep "server_pub:" | awk '{print $2}')
PSK=$(echo "$OUTPUT" | grep "psk:" | awk '{print $2}')

echo "$PRIV" > /etc/mirage/server.key
echo "$PSK" > /etc/mirage/psk.key
chmod 600 /etc/mirage/server.key /etc/mirage/psk.key

# Write systemd service
cat > /etc/systemd/system/mirage.service <<EOF
[Unit]
Description=Mirage Reality Proxy Server
After=network.target

[Service]
ExecStart=/usr/local/bin/mirage server -listen :8443 -priv-file /etc/mirage/server.key -psk-file /etc/mirage/psk.key -dest www.google.com:443 -quic
Restart=always
User=root
LimitNOFILE=512000

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable mirage
systemctl restart mirage

SERVER_IP=$(curl -s ifconfig.me)

echo ""
echo "========================================="
echo "Mirage installed and running successfully!"
echo "Port: 8443 (TCP and QUIC)"
echo ""
echo "Your Client Configuration Details:"
echo "Server IP:   $SERVER_IP"
echo "Server Port: 8443"
echo "Public Key:  $PUB"
echo "PSK:         $PSK"
echo "========================================="
echo ""
echo "To view logs: journalctl -u mirage -f"
