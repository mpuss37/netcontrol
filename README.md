# NetControl

Alat kontrol jaringan untuk Linux: **memutus (cut)**, **membatasi bandwidth (limit)**,
**membanjiri (ping flood)**, dan **melindungi** komputer dari serangan ARP spoofing
di jaringan lokal. Mendukung **IPv4 dan IPv6**.

Antarmuka grafis berbasis **PyQt5** dengan tema **gelap & terang**.

## Fitur
- Pindai & tampilkan semua host di LAN (IP, MAC, hostname, IPv6, status, alias).
- **Cut** koneksi host mana pun (IPv4 + IPv6) — benar-benar terputus.
- **Resume** mengembalikan koneksi host.
- **Limit bandwidth** per host (upload & download) seperti NetCut.
- **Limit ALL / Resume ALL** untuk banyak host sekaligus.
- **Ping Flooder** — banjiri ICMP untuk menaikkan latensi/lag target
  (preset Rendah/Sedang/Tinggi/Ekstrem + kustom pps & ukuran paket, bisa massal).
- **Proteksi ARP** untuk komputer ini.
- Ganti MAC address.
- Alias host (berdasarkan MAC).
- Tema gelap/terang (tombol toggle, tersimpan di `~/.netcontrol/`).

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
```

GUI dan daemon terpisah lewat HTTP API di `127.0.0.1:8013`.

## Instalasi (sistem ini)
Sudah terpasang:
- Aplikasi: `/opt/netcontrol/`
- Launcher: `/usr/bin/netcontrol`
- Service: `/etc/init.d/netcontrold` (aktif saat boot)
- Menu: `/usr/share/applications/netcontrol.desktop`

## Menjalankan
```bash
sudo rc-service netcontrold start      # jalankan daemon
sudo netcontrol                        # buka GUI (auto-start daemon bila perlu)
```

## Konfigurasi
- Alias host: `~/.netcontrol/aliases.db`
- Preferensi tema: `~/.netcontrol/netcontrol.conf`
- Log daemon: `/var/log/netcontrol/`

## Dependensi
- Python 3
- PyQt5
- bottle, waitress, scapy, apscheduler, netifaces, setproctitle, requests
- iptables, ip6tables, arptables, tc, conntrack, arp-scan (opsional), nmap (opsional)

Lihat `requirements.txt`.
