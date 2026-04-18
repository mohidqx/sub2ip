#!/bin/bash
# Build script for sub2ip and ip2sub
# Automatically compiles both binaries and installs to /usr/local/bin

set -e

echo "[*] Building sub2ip and ip2sub..."

# Build sub2ip binary
go build -o sub2ip main.go

if [ ! -f sub2ip ]; then
    echo "[ERR] Build failed: sub2ip binary not created"
    exit 1
fi

echo "[+] Binary compiled: sub2ip ($(du -h sub2ip | cut -f1))"

# Create ip2sub as a copy
cp sub2ip ip2sub
echo "[+] Copy created: ip2sub"

# Install to /usr/local/bin
echo "[*] Installing to /usr/local/bin..."

if [ -w /usr/local/bin ]; then
    # No sudo needed
    mv sub2ip /usr/local/bin/sub2ip
    mv ip2sub /usr/local/bin/ip2sub
    chmod +x /usr/local/bin/sub2ip /usr/local/bin/ip2sub
    echo "[+] Installed without sudo"
else
    # Sudo needed
    sudo mv sub2ip /usr/local/bin/sub2ip
    sudo mv ip2sub /usr/local/bin/ip2sub
    sudo chmod +x /usr/local/bin/sub2ip /usr/local/bin/ip2sub
    echo "[+] Installed with sudo"
fi

# Verify installation
echo ""
echo "[*] Verifying installation..."
which sub2ip >/dev/null && echo "[+] sub2ip installed: $(which sub2ip)"
which ip2sub >/dev/null && echo "[+] ip2sub installed: $(which ip2sub)"

# Show versions
echo ""
echo "[*] Version info:"
sub2ip --version
ip2sub --version

# Show banners
echo ""
echo "[*] Testing banners..."
echo ""
echo "=== sub2ip banner ==="
sub2ip --no-banner 2>&1 | head -1 >/dev/null && echo "sub2ip ready" || true

echo ""
echo "=== ip2sub banner ==="
ip2sub --no-banner 2>&1 | head -1 >/dev/null && echo "ip2sub ready" || true

echo ""
echo "[✓] Build and installation complete!"
echo ""
echo "Usage examples:"
echo "  sub2ip -d google.com --all-records -v"
echo "  ip2sub -d 8.8.8.8 -v"
echo "  sub2ip --reverse -f ips.txt -o domains.txt"
