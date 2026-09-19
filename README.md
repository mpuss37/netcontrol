# NetControl

Alat kontrol jaringan untuk Linux: **memutus (cut)**, **membatasi bandwidth (limit)**,
**membanjiri (ping flood)**, dan **melindungi** komputer dari serangan ARP spoofing
di jaringan lokal. Mendukung **IPv4 dan IPv6**.

Antarmuka grafis berbasis **PyQt5** dengan tema **gelap & terang**.

NetControl adalah alat *ofensif*; pasangan defensifnya adalah **NetView**
(monitor/deteksi/proteksi). Keduanya bisa berjalan bersamaan.

---

## Fitur
- Pindai & tampilkan semua host di LAN (IP, MAC, hostname, IPv6, status, alias).
  - **Sniffer ARP persisten**: host yang pernah berkomunikasi tetap terdeteksi
    walau sedang diam saat scan (host tak terlihat > 5 menit otomatis dibuang).
- **Cut** koneksi host mana pun (IPv4 + IPv6) — benar-benar terputus.
- **Resume** mengembalikan koneksi host.
- **Limit bandwidth** per host (upload & download) seperti NetCut.
- **Limit ALL / Resume ALL** untuk banyak host sekaligus.
- **Ping Flooder** — banjiri ICMP untuk menaikkan latensi/lag target
  (preset Rendah/Sedang/Tinggi/Ekstrem + kustom pps & ukuran paket, bisa massal).
- **Proteksi ARP** untuk komputer ini.
- Ganti MAC address.
- Alias host (berdasarkan MAC).
- Tema gelap/terang (tersimpan di `~/.netcontrol/`).

---

## Arsitektur
```
netcontrol/            GUI PyQt5
    app.py             entry point
    main_window.py     window utama
    dialogs.py         dialog limit & alias
    host_model.py      model tabel host
    api.py             klien HTTP
    theme.py           stylesheet gelap/terang
server/
    server.py          daemon (bottle + scapy + iptables/ip6tables + tc)
    utils.py           ARP/NDP spoof, cut/limit, ping flood, scan
    netcontrold.init   service OpenRC (Artix)
```

GUI dan daemon terpisah lewat HTTP API di **`127.0.0.1:8013`**.

---

## Dukungan Platform

| OS | GUI (PyQt5) | Daemon (cut / limit / flood / proteksi) | Catatan |
|----|:-----------:|:---------------------------------------:|---------|
| **Arch Linux** | ✅ | ✅ full | systemd |
| **Ubuntu 22.04+** | ✅ | ✅ full | systemd |
| **Linux Mint 21/22** | ✅ | ✅ full | systemd |
| **Artix / OpenRC** | ✅ | ✅ full | sudah ada `build.sh` + `netcontrold.init` |
| **Windows (WSL2)** | ✅ | ✅ full | Jalankan di dalam WSL2 (Ubuntu/Arch) — **cara disarankan** |
| **Windows (native)** | ✅ | ❌ tidak bisa | Butuh `fcntl`, `iptables`, `arptables`, `tc` → tidak ada di Windows |
| **Termux (Android)** | ⚠️ | ❌ non-root / ✅ root | Butuh device **root** + XServer untuk GUI |

> **Penting:** Daemon **wajib root** dan **wajib Linux** karena memakai
> `iptables`, `ip6tables`, `arptables`, `tc`, `sysctl`, dan raw socket scapy.
> Di Windows native modul Python `fcntl` tidak ada, jadi daemon tidak akan start.
> **Gunakan WSL2** bila memakai Windows.

---

## Dependensi

**Python (via `requirements.txt`):**
`bottle`, `waitress`, `scapy`, `APScheduler`, `netifaces`, `setproctitle`,
`requests`, `PyQt5`

**Alat sistem:**
`iptables`, `ip6tables`, `arptables`, `tc` (iproute2), `conntrack`,
`ip` (iproute2), `arp` + `ifconfig` (net-tools), `sysctl`, `ping`,
`arp-scan` (opsional), `nmap` (opsional).

---

## Instalasi

### Arch Linux

```bash
# 1. Paket sistem
sudo pacman -S --needed python python-pip python-pyqt5 \
    iptables iproute2 arptables conntrack-tools net-tools \
    arp-scan nmap git

# 2. Ambil source
git clone https://github.com/mpuss37/netcontrol.git
cd netcontrol

# 3. Dependensi Python (di dalam venv, hindari konflik PEP 668)
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 4. Deploy ke sistem (root) — install /opt + launcher + service systemd
sudo mkdir -p /opt/netcontrol
sudo cp -a netcontrol server assets /opt/netcontrol/
# lalu buat unit systemd (lihat bagian "Service" di bawah) & salin launcher:
sudo cp launcher /usr/bin/netcontrol && sudo chmod 755 /usr/bin/netcontrol
```

### Ubuntu 22.04 / 24.04

```bash
# 1. Paket sistem
sudo apt update
sudo apt install -y python3 python3-pip python3-venv python3-pyqt5 \
    iptables arptables iproute2 conntrack net-tools \
    arp-scan nmap git

# 2. Ambil source
git clone https://github.com/mpuss37/netcontrol.git
cd netcontrol

# 3. Dependensi Python
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 4. Deploy (lihat bagian "Service" untuk membuat unit systemd)
sudo cp -a netcontrol server assets /opt/netcontrol/
```

> Di Ubuntu 24.04 `arptables` kadang bernama `arptables-nft`. Bila tidak ada,
> pakai `sudo apt install arptables-nft` (atau `arptables`).

### Linux Mint 21 / 22

Sama seperti Ubuntu (Mint berbasis Ubuntu):

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv python3-pyqt5 \
    iptables arptables iproute2 conntrack net-tools \
    arp-scan nmap git
git clone https://github.com/mpuss37/netcontrol.git
cd netcontrol
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### Windows (disarankan: WSL2)

Daemon **tidak bisa** jalan di Windows native. Cara paling stabil = **WSL2**
(Ubuntu di dalam Windows, full Linux):

```powershell
# Di PowerShell (sebagai admin), sekali saja:
wsl --install -d Ubuntu
```

Lalu **di dalam terminal WSL2 (Ubuntu)**, ikuti langkah **Ubuntu** di atas.

- GUI PyQt5 tampil lewat **WSLg** (Windows 11 / Windows 10 terbaru sudah
  menyertakan WSLg, tidak perlu X server manual).
- Jalankan GUI dengan `sudo netcontrol`.

### Windows (native — GUI saja, fitur terbatas)

Hanya untuk **melihat** aplikasi; daemon cut/limit/flood **tidak** berfungsi.

```powershell
# 1. Pasang Python 3.11+ dari https://python.org (centang "Add to PATH")
# 2. Pasang Npcap (untuk scapy sniff): https://npcap.com/
pip install PyQt5 bottle waitress scapy netifaces requests
```

> Daemon akan gagal start (modul `fcntl` tidak ada di Windows). Arahkan ke WSL2.

### Termux (Android)

Butuh device **root** untuk fitur daemon. Untuk GUI perlu XServer.

```bash
pkg update && pkg upgrade
pkg install -y python clang git
# GUI PyQt5 (butuh repo X11)
pkg install -y x11-repo
pkg install -y python-pyqt5
# Dependensi python
pip install bottle waitress scapy netifaces requests psutil

# Fitur daemon (cut/limit/flood/proteksi) butuh root:
su -c 'iptables -L'      # pastikan root tersedia
```

- GUI: jalankan **Termux:X11** atau **XServer XSDL**, set `export DISPLAY=:0`,
  lalu buka aplikasi.
- Tanpa root: hanya bisa **menampilkan GUI**, semua aksi jaringan akan gagal.

---

## Service (auto-start daemon)

### systemd (Arch / Ubuntu / Mint)

Buat `/etc/systemd/system/netcontrold.service`:

```ini
[Unit]
Description=NetControl daemon (ARP/network cutter & bandwidth limiter)
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/netcontrol/server/server.py
WorkingDirectory=/opt/netcontrol/server
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

Aktifkan:

```bash
sudo mkdir -p /var/log/netcontrol
sudo systemctl daemon-reload
sudo systemctl enable --now netcontrold
sudo systemctl status netcontrold
```

### OpenRC (Artix)

Sudah disediakan `build.sh` + `server/netcontrold.init`:

```bash
sudo ./build.sh
```

---

## Menjalankan

```bash
# Linux (systemd): jalankan daemon
sudo systemctl start netcontrold

# Buka GUI (auto-start daemon bila server belum jalan)
sudo netcontrol
```

Bila memakai `build.sh` (OpenRC):

```bash
sudo rc-service netcontrold start
sudo netcontrol
```

Titik API: `http://127.0.0.1:8013/status` (cek server hidup).

---

## Konfigurasi

- Alias host: `~/.netcontrol/aliases.db`
- Preferensi tema: `~/.netcontrol/netcontrol.conf`
- Log daemon: `/var/log/netcontrol/`

---

## Troubleshooting

| Masalah | Penyebab / Solusi |
|---|---|
| `NameError: QApplication is not defined` | Versi lama; sudah diperbaiki. `git pull`. |
| `ModuleNotFoundError: fcntl` (Windows) | Daemon tidak untuk Windows native → pakai WSL2. |
| Server gagal start | Cek `/var/log/netcontrol/netcontrold.out`. Pastikan dijalankan `sudo`. |
| `arptables: command not found` | Pasang `arptables` (Arch/Artix) atau `arptables-nft` (Ubuntu 24.04). |
| Cut tidak berefek | Pastikan **IP forwarding** diizinkan & jalankan sebagai root; cek `sysctl net.ipv4.ip_forward`. |
| GUI tidak muncul di WSL2 | `wsl --update`; pastikan WSLg aktif (Windows 11). |
| GUI tidak muncul di Termux | Jalankan XServer (Termux:X11), set `DISPLAY`. |

---

## Etika & Legal

Alat ini untuk **administrasi jaringan sendiri / uji lab**. Memutus, membatasi,
atau membanjiri host yang **bukan milik Anda** tanpa izin **melanggar hukum**.
Gunakan hanya di jaringan yang Anda kelola atau dengan izin tertulis.
