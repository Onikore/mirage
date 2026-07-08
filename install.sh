#!/bin/bash
set -e

echo "Starting Mirage installation..."

# Ensure root
if [ "$EUID" -ne 0 ]; then 
  echo "Please run as root"
  exit 1
fi

# Install dependencies if missing
if ! command -v go &> /dev/null; then
    echo "Installing Go..."
    apt-get update && apt-get install -y golang
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

echo ""
echo "========================================="
echo "Mirage installed and running successfully!"
echo "Port: 8443 (TCP and QUIC)"
echo ""
echo "Your Client Configuration Details:"
echo "Server IP:   \$(curl -s ifconfig.me)"
echo "Server Port: 8443"
echo "Public Key:  $PUB"
echo "PSK:         $PSK"
echo "========================================="
echo ""
echo "To view logs: journalctl -u mirage -f"
