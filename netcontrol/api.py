"""
Klien HTTP ke server NetControl (127.0.0.1:8013).

Semua akses jaringan dipusatkan di sini supaya GUI tetap bersih dan
mudah diuji. Setiap fungsi mengembalikan dict hasil JSON dari server.
"""
import requests

BASE = 'http://127.0.0.1:8013'


class ApiError(Exception):
    """Dilempar bila server tidak bisa dihubungi atau membalas error."""


def _get(path, timeout=10):
    try:
        r = requests.get(BASE + path, timeout=timeout)
    except requests.exceptions.RequestException as e:
        raise ApiError('Tidak bisa menghubungi server: {}'.format(e))
    try:
        return r.json()
    except ValueError:
        raise ApiError('Balasan server tidak valid (bukan JSON)')


def _post(path, payload, timeout=30):
    try:
        r = requests.post(BASE + path, json=payload, timeout=timeout)
    except requests.exceptions.RequestException as e:
        raise ApiError('Tidak bisa menghubungi server: {}'.format(e))
    try:
        return r.json()
    except ValueError:
        raise ApiError('Balasan server tidak valid (bukan JSON)')


# ── status & info ──────────────────────────────────────────────────
def is_server_up(timeout=3):
    try:
        d = _get('/status', timeout=timeout)
        return d.get('status') == 'success'
    except ApiError:
        return False


def get_gateway():
    d = _get('/gw')
    if d.get('status') != 'success':
        raise ApiError(d.get('msg', 'gateway tidak tersedia'))
    return d['gw']


def get_my(iface):
    d = _get('/my/{}'.format(iface))
    if d.get('status') != 'success':
        raise ApiError(d.get('msg', 'info device gagal diambil'))
    return d['my']


# ── scan ───────────────────────────────────────────────────────────
def scan(gw_ip, timeout=90):
    d = _get('/scan/{}'.format(gw_ip), timeout=timeout)
    res = d.get('result', {})
    return res.get('hosts', []), res.get('ipv6_network', False)


# ── cut / resume ───────────────────────────────────────────────────
def cut(host):
    return _post('/cut', host)


def resume(host):
    return _post('/resume', host)


def resume_all(hosts):
    return _post('/resume-all', {'hosts': hosts}, timeout=60)


# ── limit bandwidth ────────────────────────────────────────────────
def limit(host, upload_kbit, download_kbit):
    payload = dict(host)
    payload['upload'] = upload_kbit
    payload['download'] = download_kbit
    return _post('/limit', payload)


def unlimit(host):
    return _post('/unlimit', host)


def limit_all(hosts, selected, upload_kbit, download_kbit):
    return _post('/limit-all', {
        'hosts': hosts,
        'selected': list(selected),
        'upload': upload_kbit,
        'download': download_kbit,
    }, timeout=90)


# ── ping flooder ───────────────────────────────────────────────────
def ping_flood(host, hz, size):
    payload = dict(host)
    payload['hz'] = hz
    payload['size'] = size
    return _post('/flood', payload)


def ping_flood_all(hosts, selected, hz, size):
    return _post('/flood-all', {
        'hosts': hosts,
        'selected': list(selected),
        'hz': hz,
        'size': size,
    }, timeout=90)


def ping_flood_stop(host):
    return _post('/unflood', host)


def ping_flood_stop_all():
    return _post('/unflood-all', {})


def ping_flood_status(timeout=5):
    d = _get('/flood-status', timeout=timeout)
    return d.get('floods', {})


def overview(timeout=6):
    return _get('/overview', timeout=timeout)


# ── proteksi & MAC ─────────────────────────────────────────────────
def protect(gw):
    return _post('/protect', gw)


def unprotect():
    return _get('/unprotect')


def change_mac(iface):
    return _get('/change-mac/{}'.format(iface), timeout=20)
