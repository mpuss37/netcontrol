#!/bin/bash
# ============================================================
#  NetControl - deploy ke sistem (Artix/OpenRC)
#  Jalankan sebagai root:  sudo ./build.sh
# ============================================================
set -e

SRC_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Butuh root. Jalankan: sudo ./build.sh"
    exit 1
fi

echo "[*] Deploy aplikasi ke /opt/netcontrol ..."
rm -rf /opt/netcontrol
mkdir -p /opt/netcontrol
cp -a "$SRC_DIR/netcontrol" /opt/netcontrol/netcontrol
cp -a "$SRC_DIR/server" /opt/netcontrol/server
cp -a "$SRC_DIR/assets" /opt/netcontrol/assets
cp "$SRC_DIR/netcontrol.desktop" /opt/netcontrol/
rm -rf /opt/netcontrol/netcontrol/__pycache__ /opt/netcontrol/server/__pycache__

echo "[*] Install launcher /usr/bin/netcontrol ..."
cp "$SRC_DIR/launcher" /usr/bin/netcontrol
chmod 755 /usr/bin/netcontrol

echo "[*] Install service /etc/init.d/netcontrold ..."
cp "$SRC_DIR/server/netcontrold.init" /etc/init.d/netcontrold
chmod 755 /etc/init.d/netcontrold
rc-update add netcontrold default 2>/dev/null || true

echo "[*] Install desktop entry & ikon ..."
cp "$SRC_DIR/netcontrol.desktop" /usr/share/applications/netcontrol.desktop
cp "$SRC_DIR/assets/ninja_32.png" /usr/share/pixmaps/netcontrol.png

echo "[*] Siapkan direktori log ..."
mkdir -p /var/log/netcontrol

echo "[*] Restart service ..."
rc-service netcontrold restart || rc-service netcontrold start

echo "[+] Selesai. Jalankan GUI dengan:  sudo netcontrol"
