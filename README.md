# NetControl

NetControl adalah alat kontrol jaringan: memutus (cut), membatasi bandwidth,
membanjiri dengan ping, dan melindungi komputer dari serangan ARP spoofing di
jaringan lokal. Mendukung IPv4 dan IPv6.

Antarmuka grafisnya memakai PyQt5, dengan tema gelap dan terang.

NetControl bersifat ofensif. Pasangan defensifnya adalah NetView, yang memantau
jaringan dan mendeteksi ARP spoof. Keduanya bisa jalan bersamaan.

## Fitur

- Memindai dan menampilkan semua host di LAN: IP, MAC, hostname, IPv6, status, alias.
  Ada sniffer ARP persisten yang membuat host yang pernah berkomunikasi tetap
  terdeteksi walau sedang diam saat scan. Host yang tidak terlihat lebih dari
  lima menit otomatis dibuang.
- Cut koneksi host mana pun, IPv4 maupun IPv6. Koneksinya benar-benar putus.
- Resume untuk mengembalikan koneksi host.
- Batasi bandwidth per host, upload dan download, seperti NetCut.
- Limit All dan Resume All untuk banyak host sekaligus.
- Ping Flooder untuk menaikkan latensi target. Ada preset Rendah, Sedang, Tinggi,
  Ekstrem, plus opsi kustom pps dan ukuran paket. Bisa massal.
- Proteksi ARP untuk komputer ini.
- Ganti MAC address.
- Alias host berdasarkan MAC.
- Tema gelap/terang, tersimpan di `~/.netcontrol/`.

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

GUI dan daemon terpisah, berkomunikasi lewat HTTP API di `127.0.0.1:8013`.

## Dukungan platform

| OS | GUI (PyQt5) | Daemon (cut, limit, flood, proteksi) | Catatan |
|----|:-----------:|:------------------------------------:|---------|
| Arch Linux | bisa | bisa, full | systemd |
| Ubuntu 22.04+ | bisa | bisa, full | systemd |
| Linux Mint 21/22 | bisa | bisa, full | systemd |
| Artix / OpenRC | bisa | bisa, full | ada `build.sh` dan `netcontrold.init` |
| Windows lewat WSL2 | bisa | bisa, full | cara yang disarankan untuk Windows |
| Windows native | bisa | tidak bisa | butuh `fcntl`, `iptables`, `arptables`, `tc` yang tidak ada di Windows |
| Termux Android | dengan usaha ekstra | butuh root | perlu device root dan XServer untuk GUI |

Daemon wajib root dan wajib Linux, karena memakai `iptables`, `ip6tables`,
`arptables`, `tc`, `sysctl`, dan raw socket scapy. Di Windows native modul Python
`fcntl` tidak tersedia, jadi daemon tidak akan start. Kalau memakai Windows,
jalankan lewat WSL2.

## Dependensi

Paket Python (lihat `requirements.txt`):
`bottle`, `waitress`, `scapy`, `APScheduler`, `netifaces`, `setproctitle`,
`requests`, `PyQt5`

Alat sistem:
`iptables`, `ip6tables`, `arptables`, `tc` (iproute2), `conntrack`,
`ip` (iproute2), `arp` dan `ifconfig` (net-tools), `sysctl`, `ping`,
`arp-scan` (opsional), `nmap` (opsional).

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

# 3. Dependensi Python. Pakai venv supaya tidak bentrok dengan PEP 668.
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 4. Deploy ke sistem
sudo mkdir -p /opt/netcontrol
sudo cp -a netcontrol server assets /opt/netcontrol/
sudo cp launcher /usr/bin/netcontrol && sudo chmod 755 /usr/bin/netcontrol
# lalu buat unit systemd, lihat bagian Service di bawah
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

# 4. Deploy
sudo mkdir -p /opt/netcontrol
sudo cp -a netcontrol server assets /opt/netcontrol/
sudo cp launcher /usr/bin/netcontrol && sudo chmod 755 /usr/bin/netcontrol
```

Di Ubuntu 24.04, `arptables` kadang ada di paket `arptables-nft`. Kalau tidak
ketemu, pakai `sudo apt install arptables-nft`.

### Linux Mint 21 / 22

Mint berbasis Ubuntu, jadi langkahnya sama:

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv python3-pyqt5 \
    iptables arptables iproute2 conntrack net-tools \
    arp-scan nmap git
git clone https://github.com/mpuss37/netcontrol.git
cd netcontrol
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
sudo mkdir -p /opt/netcontrol
sudo cp -a netcontrol server assets /opt/netcontrol/
sudo cp launcher /usr/bin/netcontrol && sudo chmod 755 /usr/bin/netcontrol
```

### Windows

Daemon tidak bisa jalan di Windows native. Pilihan yang stabil adalah WSL2, yang
menjalankan Ubuntu penuh di dalam Windows. Di PowerShell sebagai admin, sekali saja:

```powershell
wsl --install -d Ubuntu
```

Setelah itu, di dalam terminal WSL2, ikuti langkah Ubuntu di atas. GUI muncul
lewat WSLg, yang sudah tersedia di Windows 11 dan Windows 10 versi terbaru tanpa
perlu X server manual. Jalankan dengan `sudo netcontrol`.

Kalau tetap ingin coba di Windows native, hanya GUI yang bisa dibuka:

```powershell
# Pasang Python 3.11+ dari python.org, centang "Add to PATH"
# Pasang Npcap dari https://npcap.com/ untuk scapy
pip install PyQt5 bottle waitress scapy netifaces requests
```

Daemon akan gagal start karena modul `fcntl` tidak ada di Windows.

### Termux (Android)

Fitur daemon butuh device yang sudah di-root. GUI butuh XServer.

```bash
pkg update && pkg upgrade
pkg install -y python clang git
pkg install -y x11-repo
pkg install -y python-pyqt5
pip install bottle waitress scapy netifaces requests psutil

# Cek root untuk fitur daemon
su -c 'iptables -L'
```

Untuk GUI, jalankan Termux:X11 atau XServer XSDL, set `export DISPLAY=:0`, lalu
buka aplikasi. Tanpa root, hanya GUI yang tampil dan semua aksi jaringan gagal.

## Service (auto-start daemon)

### systemd (Arch, Ubuntu, Mint)

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

Aktifkan dengan:

```bash
sudo mkdir -p /var/log/netcontrol
sudo systemctl daemon-reload
sudo systemctl enable --now netcontrold
sudo systemctl status netcontrold
```

### OpenRC (Artix)

`build.sh` dan `server/netcontrold.init` sudah disiapkan untuk OpenRC:

```bash
sudo ./build.sh
```

## Menjalankan

Di Linux dengan systemd:

```bash
sudo systemctl start netcontrold
sudo netcontrol
```

Launcher `netcontrol` akan menyalakan daemon kalau belum jalan. Dengan OpenRC,
ganti baris pertama dengan `sudo rc-service netcontrold start`.

Untuk memastikan server hidup, cek `http://127.0.0.1:8013/status`.

## Konfigurasi

- Alias host: `~/.netcontrol/aliases.db`
- Preferensi tema: `~/.netcontrol/netcontrol.conf`
- Log daemon: `/var/log/netcontrol/`

## Troubleshooting

| Masalah | Penyebab dan solusi |
|---|---|
| `NameError: QApplication is not defined` | Versi lama. Jalankan `git pull`. |
| `ModuleNotFoundError: fcntl` di Windows | Daemon memang bukan untuk Windows native. Pakai WSL2. |
| Server gagal start | Cek `/var/log/netcontrol/netcontrold.out`. Pastikan dijalankan dengan sudo. |
| `arptables: command not found` | Pasang `arptables`, atau `arptables-nft` di Ubuntu 24.04. |
| Cut tidak berefek | Pastikan IP forwarding diizinkan dan dijalankan sebagai root. Cek `sysctl net.ipv4.ip_forward`. |
| GUI tidak muncul di WSL2 | Jalankan `wsl --update` dan pastikan WSLg aktif. |
| GUI tidak muncul di Termux | Jalankan XServer, lalu set `DISPLAY`. |

## Etika dan legal

Alat ini dibuat untuk administrasi jaringan sendiri dan pengujian di lab. Memutus,
membatasi, atau membanjiri host yang bukan milik Anda tanpa izin melanggar hukum.
Pakai hanya di jaringan yang Anda kelola atau yang sudah ada izin tertulis.
