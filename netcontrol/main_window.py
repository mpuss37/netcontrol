"""
Window utama NetControl (PyQt5).

Fitur (identik dengan versi lama):
  - tabel host (status text, IP, MAC, Hostname, IPv6, Status, Alias)
  - toolbar: Refresh, Cut/Resume, Resume, Speed, Limit All, Resume All,
    Change MAC, Alias, Toggle Tema, Exit
  - proteksi ARP (checkbox)
  - status bar
  - title bar info GW/iface/device + status IPv6
  - tema gelap/terang
"""
import os
import shelve
from pathlib import Path

from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTableView, QCheckBox,
    QToolBar, QAction, QLabel, QMessageBox, QHeaderView, QApplication,
    QAbstractItemView, QTabWidget, QPlainTextEdit,
)

from . import api, theme
from .host_model import HostModel, COL_IP, COL_MAC, COL_HOSTNAME, COL_ALIAS
from .dialogs import SpeedDialog, LimitAllDialog, AliasDialog, FloodDialog

APP_DIR = os.path.join(str(Path.home()), '.netcontrol')


# ── worker scan (thread) ───────────────────────────────────────────
class ScanWorker(QThread):
    done = pyqtSignal(list, bool)
    failed = pyqtSignal(str)

    def __init__(self, gw_ip):
        super().__init__()
        self.gw_ip = gw_ip

    def run(self):
        try:
            hosts, ipv6 = api.scan(self.gw_ip)
            self.done.emit(hosts, ipv6)
        except api.ApiError as e:
            self.failed.emit(str(e))


# ── worker umum (cut/resume/limit) ─────────────────────────────────
class ActionWorker(QThread):
    done = pyqtSignal(str, dict, str)      # (kind, result, ip)
    failed = pyqtSignal(str, str)          # (kind, error)

    def __init__(self, kind, fn, ip=''):
        super().__init__()
        self.kind = kind
        self.fn = fn
        self.ip = ip

    def run(self):
        try:
            self.done.emit(self.kind, self.fn(), self.ip)
        except api.ApiError as e:
            self.failed.emit(self.kind, str(e))


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self._gw = {}
        self._my = {}
        self._ipv6_net = False
        self._theme = theme.load_pref()

        # aliases (shelve) di ~/.netcontrol/aliases.db
        os.makedirs(APP_DIR, exist_ok=True)
        self.aliases = shelve.open(os.path.join(APP_DIR, 'aliases.db'))

        self._workers = []
        self._scan_worker = None

        self._build_ui()
        self._apply_theme(self._theme)

        if not api.is_server_up():
            QMessageBox.critical(
                self, 'Server tidak berjalan',
                'Server NetControl tidak berjalan.\n'
                'Jalankan: sudo rc-service netcontrold start\n'
                'lalu buka ulang aplikasi.')
            raise SystemExit(1)

        self._load_gw()
        self.refresh()

    # ── UI ─────────────────────────────────────────────────────────
    def _build_ui(self):
        self.setWindowTitle('NetControl')
        self.resize(820, 460)

        central = QWidget()
        self.setCentralWidget(central)
        v = QVBoxLayout(central)

        top = QHBoxLayout()
        self.cb_protection = QCheckBox('Protect My Computer')
        self.cb_protection.toggled.connect(self._toggle_protection)
        top.addWidget(self.cb_protection)
        top.addStretch(1)
        v.addLayout(top)

        # ── panel dashboard status (2 baris, berwarna) ──
        dash = QVBoxLayout()
        dash.setContentsMargins(6, 4, 6, 2)
        dash.setSpacing(2)
        self.lbl_status = QLabel('Memuat...')
        self.lbl_status.setTextFormat(Qt.RichText)
        self.lbl_status.setWordWrap(True)
        dash.addWidget(self.lbl_status)
        self.lbl_state = QLabel('')
        self.lbl_state.setTextFormat(Qt.RichText)
        self.lbl_state.setWordWrap(True)
        dash.addWidget(self.lbl_state)
        v.addLayout(dash)

        # ── tabs: Hosts / Floods ──
        self.tabs = QTabWidget()
        v.addWidget(self.tabs, 1)

        self.model = HostModel(self)
        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.setSortingEnabled(False)
        self.table.verticalHeader().setVisible(False)
        self.table.doubleClicked.connect(self._on_double_click)
        hdr = self.table.horizontalHeader()
        hdr.setSectionResizeMode(QHeaderView.ResizeToContents)
        hdr.setStretchLastSection(True)
        self.tabs.addTab(self.table, 'Hosts')

        # tab Floods: daftar host yang sedang di-ping-flood
        self.flood_text = QPlainTextEdit()
        self.flood_text.setReadOnly(True)
        self.tabs.addTab(self.flood_text, 'Floods')

        self._build_toolbar()
        self.statusBar().showMessage('Siap')

        # refresh dashboard tiap 2 detik
        self._dash_timer = QTimer(self)
        self._dash_timer.setInterval(2000)
        self._dash_timer.timeout.connect(self._refresh_dashboard)
        self._dash_timer.start()
        self._refresh_dashboard()

    def _build_toolbar(self):
        tb = QToolBar()
        tb.setMovable(False)
        self.addToolBar(tb)

        def act(text, tip, slot, checkable=False):
            a = QAction(text, self)
            a.setToolTip(tip)
            if checkable:
                a.setCheckable(True)
            a.triggered.connect(slot)
            tb.addAction(a)
            return a

        self.act_refresh = act('Refresh', 'Refresh', self.refresh)
        self.act_cut = act('Cut', 'Cut / Resume (toggle)', self._on_cut)
        self.act_resume = act('Resume', 'Resume', self._on_resume)
        self.act_speed = act('Speed', 'Limit Bandwidth (Speed)', self._on_speed)
        tb.addSeparator()
        self.act_limit_all = act('Limit All', 'Limit ALL hosts', self._on_limit_all)
        self.act_resume_all = act('Resume All', 'Resume ALL hosts', self._on_resume_all)
        tb.addSeparator()
        self.act_mac = act('MAC', 'Change MAC Address', self._on_change_mac)
        self.act_alias = act('Alias', 'Give an alias', self._on_alias)
        tb.addSeparator()
        self.act_flood = act('Flood', 'Ping Flooder (buat lag)', self._on_flood)
        tb.addSeparator()
        self.act_theme = act('Tema', 'Toggle tema gelap/terang', self._toggle_theme)
        tb.addSeparator()
        self.act_exit = act('Exit', 'Exit', self.close)

    # ── tema ───────────────────────────────────────────────────────
    def _apply_theme(self, name):
        self._theme = name
        QApplication.instance().setStyleSheet(theme.qss(name))
        theme.save_pref(name)

    def _toggle_theme(self):
        new = theme.LIGHT if self._theme == theme.DARK else theme.DARK
        self._apply_theme(new)
        self.statusBar().showMessage(
            'Tema: {}'.format('Terang' if new == theme.LIGHT else 'Gelap'), 3000)

    # ── data ───────────────────────────────────────────────────────
    def _load_gw(self):
        try:
            self._gw = api.get_gateway()
            self._my = api.get_my(self._gw['iface'])
        except api.ApiError as e:
            QMessageBox.critical(self, 'Error', str(e))
            raise SystemExit(1)
        self._update_title()

    def _update_title(self):
        gw_ip = self._gw.get('ip', '?')
        gw_mac = self._gw.get('mac', '?')
        iface = self._gw.get('iface', '?')
        my_ip = self._my.get('ip', '?')
        v6 = 'ON' if self._ipv6_net else 'off'
        self.setWindowTitle(
            'NetControl  |  GW: {} ({}) [{}]  |  This device: {}  |  IPv6: {}'.format(
                gw_ip, gw_mac, iface, my_ip, v6))

    def refresh(self):
        self.statusBar().showMessage('Memindai jaringan ...')
        self.act_refresh.setEnabled(False)
        gw_ip = self._my.get('ip') or self._gw.get('ip')
        self._scan_worker = ScanWorker(gw_ip)
        self._scan_worker.done.connect(self._on_scan_done)
        self._scan_worker.failed.connect(self._on_scan_failed)
        self._scan_worker.start()

    def _on_scan_done(self, hosts, ipv6_net):
        self._ipv6_net = ipv6_net
        # pertahankan status cut host lama yang masih ada
        cut = self.model.cut_ips()
        # tambahkan host yang di-cut tapi tidak terdeteksi
        seen = {h['ip'] for h in hosts}
        for rec in self.model.all_hosts():
            if rec['ip'] in cut and rec['ip'] not in seen:
                hosts.append({'ip': rec['ip'], 'mac': rec['mac'],
                              'hostname': rec['hostname'], 'ipv6': rec['ipv6']})
        # alias dari shelve
        for h in hosts:
            try:
                h['alias'] = self.aliases.get(h.get('mac', ''), '')
            except Exception:
                h['alias'] = ''
        self.model.set_hosts(hosts)
        # pulihkan tanda cut yang masih aktif
        for ip in cut:
            self.model._offline.add(ip)
        self.model.update_statuses()
        self._update_title()
        self.act_refresh.setEnabled(True)
        n_cut = len(self.model.cut_ips())
        n_lim = len(self.model.limited_ips())
        parts = []
        if n_cut:
            parts.append('{} cut'.format(n_cut))
        if n_lim:
            parts.append('{} limited'.format(n_lim))
        self.statusBar().showMessage(
            'Siap - ' + ', '.join(parts) if parts else 'Siap')

    def _on_scan_failed(self, err):
        self.act_refresh.setEnabled(True)
        self.statusBar().showMessage('Scan gagal')
        QMessageBox.warning(self, 'Scan gagal', err)

    # ── helper seleksi ─────────────────────────────────────────────
    def _selected_host(self):
        idx = self.table.currentIndex()
        if not idx.isValid():
            return None
        row = idx.row()
        return {
            'ip': self.model.data(self.model.index(row, COL_IP), Qt.DisplayRole),
            'mac': self.model.data(self.model.index(row, COL_MAC), Qt.DisplayRole),
            'hostname': self.model.data(self.model.index(row, COL_HOSTNAME),
                                        Qt.DisplayRole),
            'alias': self.model.data(self.model.index(row, COL_ALIAS),
                                     Qt.DisplayRole),
        }

    def _is_gateway(self, host):
        try:
            return host['ip'] == self._gw.get('ip')
        except Exception:
            return False

    # ── aksi: cut / resume ─────────────────────────────────────────
    def _on_double_click(self, index):
        self._on_cut()

    def _on_cut(self):
        host = self._selected_host()
        if not host:
            self.statusBar().showMessage('Pilih host dulu')
            return
        if self._is_gateway(host):
            QMessageBox.warning(self, 'Tidak bisa', 'Host ini gateway.')
            return
        ip = host['ip']
        if self.model.is_cut(ip):
            self._run_action('resume', lambda: api.resume(host), ip)
        else:
            self._run_action('cut', lambda: api.cut(host), ip)

    def _on_resume(self):
        host = self._selected_host()
        if not host:
            self.statusBar().showMessage('Pilih host dulu')
            return
        self._run_action('resume', lambda: api.resume(host), host['ip'])

    def _run_action(self, kind, fn, ip=''):
        w = ActionWorker(kind, fn, ip)
        w.done.connect(self._on_action_done)
        w.failed.connect(self._on_action_failed)
        w.finished.connect(lambda: self._workers.remove(w) if w in self._workers else None)
        self._workers.append(w)
        w.start()

    def _on_action_done(self, kind, res, ip):
        if res.get('status') != 'success':
            self.statusBar().showMessage('Gagal: ' + str(res.get('msg', '')))
            return
        if kind == 'cut' and ip:
            self.model.mark_cut(ip)
            self.statusBar().showMessage('{} terputus (CUT)'.format(ip))
        elif kind == 'resume' and ip:
            self.model.mark_online(ip)
            self.statusBar().showMessage('{} kembali online'.format(ip))
        self._refresh_summary()

    def _on_action_failed(self, kind, err):
        self.statusBar().showMessage('Error: {}'.format(err))
        QMessageBox.warning(self, 'Error', err)

    # ── aksi: limit bandwith ───────────────────────────────────────
    def _on_speed(self):
        host = self._selected_host()
        if not host:
            self.statusBar().showMessage('Pilih host dulu')
            return
        if self._is_gateway(host):
            QMessageBox.warning(self, 'Tidak bisa', 'Host ini gateway.')
            return
        dlg = SpeedDialog(self, host)
        dlg.exec_()

    def notify_limited(self, ip, label):
        self.model.mark_limited(ip, label)
        self._refresh_summary()

    def notify_unlimited(self, ip):
        self.model.mark_unlimited(ip)
        self._refresh_summary()

    def _on_limit_all(self):
        hosts = self.model.all_hosts()
        if not hosts:
            QMessageBox.information(self, 'Kosong', 'Refresh dulu daftarnya.')
            return
        dlg = LimitAllDialog(self, hosts)
        dlg.exec_()

    def _on_resume_all(self):
        targets = [h for h in self.model.all_hosts()
                   if h['ip'] in self.model.cut_ips()
                   or h['ip'] in self.model.limited_ips()]
        if not targets:
            QMessageBox.information(self, 'Tidak ada',
                                    'Tidak ada host yang sedang di-cut/dilimit.')
            return
        ans = QMessageBox.question(
            self, 'Resume All',
            'Nyalakan semua {} host yang di-cut/dilimit?'.format(len(targets)),
            QMessageBox.Yes | QMessageBox.No)
        if ans != QMessageBox.Yes:
            return

        def do():
            return api.resume_all(targets)

        def finished(kind, res, ip):
            if res.get('status') == 'success':
                for h in targets:
                    self.model.mark_online(h['ip'])
                self._refresh_summary()
                self.statusBar().showMessage(
                    'Resume all: {} host online'.format(len(targets)))
            else:
                QMessageBox.warning(self, 'Gagal', str(res))

        w = ActionWorker('resume-all', do)
        w.done.connect(finished)
        w.failed.connect(lambda k, e: QMessageBox.warning(self, 'Error', e))
        w.finished.connect(lambda: self._workers.remove(w) if w in self._workers else None)
        self._workers.append(w)
        w.start()

    # ── proteksi, MAC, alias, exit ─────────────────────────────────
    def _toggle_protection(self, checked):
        try:
            if checked:
                res = api.protect(self._gw)
                if res.get('status') == 'success':
                    self.statusBar().showMessage(
                        'Proteksi aktif - komputer terlindungi')
                else:
                    self.statusBar().showMessage('Proteksi gagal')
                    self.cb_protection.setChecked(False)
            else:
                api.unprotect()
                self.statusBar().showMessage('Proteksi nonaktif')
        except api.ApiError as e:
            self.statusBar().showMessage('Error proteksi: {}'.format(e))
            self.cb_protection.setChecked(False)

    def _on_change_mac(self):
        iface = self._gw.get('iface')
        try:
            res = api.change_mac(iface)
        except api.ApiError as e:
            QMessageBox.warning(self, 'Error', str(e))
            return
        st = res.get('result', {}).get('status')
        if st == 'success':
            QMessageBox.information(self, 'OK', 'MAC address berhasil diubah.')
        else:
            QMessageBox.warning(self, 'Gagal', 'Tidak bisa mengubah MAC.')

    def _on_alias(self):
        host = self._selected_host()
        if not host:
            self.statusBar().showMessage('Pilih host dulu')
            return
        mac = host['mac']
        current = self.aliases.get(mac, '')
        dlg = AliasDialog(self, mac, current)
        if dlg.exec_() == dlg.Accepted:
            val = dlg.value()
            try:
                self.aliases[mac] = val
            except Exception:
                pass
            self.model.set_alias(host['ip'], val)
            self.statusBar().showMessage('Alias disimpan untuk {}'.format(mac))

    # ── ping flooder ───────────────────────────────────────────────
    def _on_flood(self):
        hosts = self.model.all_hosts()
        if not hosts:
            QMessageBox.information(self, 'Kosong', 'Refresh dulu daftarnya.')
            return
        dlg = FloodDialog(self, hosts)
        dlg.exec_()
        self._refresh_summary()

    def notify_flooding(self, ips):
        for ip in ips:
            self.model.mark_flooding(ip)
        if ips:
            self.statusBar().showMessage(
                'Ping flood aktif: {} host'.format(len(ips)))
        self._refresh_summary()

    def notify_unflooding(self, ips):
        for ip in ips:
            self.model.mark_unflooding(ip)
        self._refresh_summary()

    def closeEvent(self, event):
        # hentikan semua flood yang sedang jalan
        try:
            st = api.ping_flood_status()
            if st:
                api.ping_flood_stop_all()
        except Exception:
            pass
        # lepas proteksi bila aktif (meniru perilaku lama)
        try:
            if self.cb_protection.isChecked():
                api.unprotect()
        except Exception:
            pass
        try:
            self.aliases.close()
        except Exception:
            pass
        event.accept()

    def _refresh_summary(self):
        n_cut = len(self.model.cut_ips())
        n_lim = len(self.model.limited_ips())
        n_flood = len(self.model.flooding_ips())
        parts = []
        if n_cut:
            parts.append('{} cut'.format(n_cut))
        if n_lim:
            parts.append('{} limited'.format(n_lim))
        if n_flood:
            parts.append('{} flooding'.format(n_flood))
        self.statusBar().showMessage(
            'Siap - ' + ', '.join(parts) if parts else 'Siap')

    # ── dashboard status ───────────────────────────────────────────
    def _refresh_dashboard(self):
        """Ambil /overview dan tampilkan panel status 2 baris."""
        try:
            ov = api.overview()
        except api.ApiError:
            self.lbl_status.setText(
                '<span style="color:#e5484d;font-weight:600">'
                'Server tidak terhubung</span>')
            self.lbl_state.setText('')
            return

        gw = ov.get('gw', {}) or {}
        my = ov.get('my', {}) or {}
        iface = ov.get('iface', '?')
        n_host = self.model.rowCount()

        # baris 1: jaringan
        self.lbl_status.setText(
            'Iface: <b>{}</b> &nbsp;|&nbsp; '
            'Host: <b>{}</b> &nbsp;|&nbsp; '
            'Seen (ARP): <b>{}</b> &nbsp;|&nbsp; '
            'GW: <b>{}</b> ({}) &nbsp;|&nbsp; '
            'This device: <b>{}</b>'.format(
                iface, n_host,
                ov.get('seen', 0),
                gw.get('ip', '?'), gw.get('mac', '?'),
                my.get('ip', '?')))

        # baris 2: aksi aktif
        n_cut = ov.get('cut', 0)
        n_lim = ov.get('limit', 0)
        n_flood = ov.get('flood', 0)
        n_drop = ov.get('drop_rules', 0)

        def _num(v, color='#e0a52a'):
            if v > 0:
                return '<b style="color:{}">{}</b>'.format(color, v)
            return '<b style="color:#46c46a">0</b>'

        self.lbl_state.setText(
            'Cut: {} &nbsp;|&nbsp; '
            'Limit: {} &nbsp;|&nbsp; '
            'Flood: {} &nbsp;|&nbsp; '
            'DROP rules: <b>{}</b> &nbsp;|&nbsp; '
            'Victims: <b>{}</b>'.format(
                _num(n_cut, '#e5484d'), _num(n_lim, '#e0a52a'),
                _num(n_flood, '#e0a52a'), n_drop, ov.get('victims', 0)))

        # isi tab Floods
        floods = ov.get('floods', {}) or {}
        lines = []
        for ip, info in floods.items():
            lines.append('{}  ({} pps, {} B, {} pkt)'.format(
                ip, info.get('hz', '?'), info.get('size', '?'),
                info.get('sent', 0)))
        self.flood_text.setPlainText(
            chr(10).join(lines) if lines else 'Tidak ada flood aktif.')
