"""Dialog-dialog NetControl (versi PyQt5)."""
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QFormLayout, QLabel, QComboBox,
    QPushButton, QCheckBox, QScrollArea, QWidget, QLineEdit, QMessageBox,
    QSpinBox, QGroupBox,
)

from . import api

SPEEDS = [
    ('Unlimited', 0),
    ('20 Mbit', 20000),
    ('10 Mbit', 10000),
    ('5 Mbit', 5000),
    ('2 Mbit', 2000),
    ('1 Mbit', 1000),
    ('512 kbit', 512),
    ('256 kbit', 256),
    ('128 kbit', 128),
    ('64 kbit', 64),
    ('32 kbit', 32),
]


def _speed_combo():
    cb = QComboBox()
    for label, _ in SPEEDS:
        cb.addItem(label)
    cb.setCurrentIndex(0)
    return cb


def _speed_value(cb):
    return SPEEDS[cb.currentIndex()][1]


class SpeedDialog(QDialog):
    """Atur limit bandwidth untuk satu host."""

    def __init__(self, parent, target):
        super().__init__(parent)
        self.target = target
        self.setWindowTitle('Limit Bandwidth - {}'.format(target['ip']))
        self.setMinimumWidth(420)

        v = QVBoxLayout(self)
        head = QLabel('Host: {}   ({})'.format(
            target['ip'], target.get('hostname') or '-'))
        v.addWidget(head)

        form = QFormLayout()
        self.dl = _speed_combo()
        self.ul = _speed_combo()
        form.addRow('Download limit (server \u2192 target):', self.dl)
        form.addRow('Upload limit (target \u2192 internet):', self.ul)
        v.addLayout(form)

        h = QHBoxLayout()
        self.btn_apply = QPushButton('Apply Limit')
        self.btn_remove = QPushButton('Remove Limit')
        self.btn_close = QPushButton('Close')
        h.addWidget(self.btn_apply)
        h.addWidget(self.btn_remove)
        h.addStretch(1)
        h.addWidget(self.btn_close)
        v.addLayout(h)

        self.status = QLabel('')
        v.addWidget(self.status)

        self.btn_apply.clicked.connect(self.on_apply)
        self.btn_remove.clicked.connect(self.on_remove)
        self.btn_close.clicked.connect(self.reject)

    def on_apply(self):
        dl = _speed_value(self.dl)
        ul = _speed_value(self.ul)
        if dl == 0 and ul == 0:
            self.on_remove()
            return
        try:
            res = api.limit(self.target, ul, dl)
            if res.get('status') == 'success':
                label = '{}k/{}k'.format(ul, dl)
                self.parent().notify_limited(self.target['ip'], label)
                self.status.setText('OK: ' + res.get('msg', ''))
            else:
                self.status.setText('FAILED: ' + str(res.get('msg', '')))
        except api.ApiError as e:
            self.status.setText('ERROR: {}'.format(e))

    def on_remove(self):
        try:
            res = api.unlimit(self.target)
            if res.get('status') == 'success':
                self.parent().notify_unlimited(self.target['ip'])
                self.status.setText('OK: limit dihapus')
            else:
                self.status.setText('FAILED: ' + str(res.get('msg', '')))
        except api.ApiError as e:
            self.status.setText('ERROR: {}'.format(e))


class LimitAllDialog(QDialog):
    """Limit bandwidth massal dengan daftar centang host."""

    def __init__(self, parent, hosts):
        super().__init__(parent)
        self.hosts = hosts
        self.setWindowTitle('Limit ALL Hosts (Mass Limit)')
        self.setMinimumSize(520, 520)

        v = QVBoxLayout(self)
        v.addWidget(QLabel('Terapkan batas kecepatan ke host terpilih:'))

        form = QFormLayout()
        self.dl = _speed_combo()
        self.ul = _speed_combo()
        form.addRow('Download limit:', self.dl)
        form.addRow('Upload limit:', self.ul)
        v.addLayout(form)

        v.addWidget(QLabel('Pilih host yang AKAN DILIMIT (centang = dilimit):'))

        # daftar checkbox dalam scroll area
        area = QScrollArea()
        area.setWidgetResizable(True)
        inner = QWidget()
        from PyQt5.QtWidgets import QVBoxLayout as _V
        self._inner_layout = _V(inner)
        area.setWidget(inner)
        v.addWidget(area, 1)

        self.checkboxes = {}
        for h in hosts:
            hname = h.get('hostname', '') or ''
            is_gw = '(GATEWAY)' in hname
            label = '{}   {}'.format(h['ip'], hname)
            cb = QCheckBox(label)
            if is_gw:
                cb.setChecked(False)
                cb.setEnabled(False)     # gateway tidak boleh dilimit
            else:
                cb.setChecked(True)
            self.checkboxes[h['ip']] = cb
            self._inner_layout.addWidget(cb)
        self._inner_layout.addStretch(1)

        h = QHBoxLayout()
        self.btn_all = QPushButton('Check All')
        self.btn_none = QPushButton('Uncheck All')
        self.btn_apply = QPushButton('Apply to All')
        self.btn_close = QPushButton('Close')
        h.addWidget(self.btn_all)
        h.addWidget(self.btn_none)
        h.addStretch(1)
        h.addWidget(self.btn_apply)
        h.addWidget(self.btn_close)
        v.addLayout(h)

        self.status = QLabel('')
        v.addWidget(self.status)

        self.btn_all.clicked.connect(self._check_all)
        self.btn_none.clicked.connect(self._uncheck_all)
        self.btn_apply.clicked.connect(self._apply)
        self.btn_close.clicked.connect(self.reject)

    def _check_all(self):
        for cb in self.checkboxes.values():
            if cb.isEnabled():
                cb.setChecked(True)

    def _uncheck_all(self):
        for cb in self.checkboxes.values():
            if cb.isEnabled():
                cb.setChecked(False)

    def _apply(self):
        dl = _speed_value(self.dl)
        ul = _speed_value(self.ul)
        if dl == 0 and ul == 0:
            self.status.setText('Pilih limit dulu (bukan Unlimited).')
            return
        selected = [ip for ip, cb in self.checkboxes.items() if cb.isChecked()]
        if not selected:
            self.status.setText('Tidak ada host yang dipilih untuk dilimit.')
            return

        self.status.setText('Menerapkan ke {} host...'.format(len(selected)))
        self.btn_apply.setEnabled(False)
        try:
            res = api.limit_all(self.hosts, selected, ul, dl)
            if res.get('status') == 'success':
                done = res.get('done', [])
                label = '{}k/{}k'.format(ul, dl)
                for ip in done:
                    self.parent().notify_limited(ip, label)
                self.status.setText('OK: {} host dilimit, {} dikecualikan'.format(
                    len(done), len(res.get('excluded', []))))
            else:
                self.status.setText('FAILED: ' + str(res.get('msg', '')))
        except api.ApiError as e:
            self.status.setText('ERROR: {}'.format(e))
        finally:
            self.btn_apply.setEnabled(True)


class AliasDialog(QDialog):
    """Beri alias untuk sebuah host (berdasarkan MAC)."""

    def __init__(self, parent, mac, current=''):
        super().__init__(parent)
        self.setWindowTitle('Alias untuk {}'.format(mac))
        self.setMinimumWidth(360)
        v = QVBoxLayout(self)
        v.addWidget(QLabel('Masukkan alias untuk host dengan MAC "{}":'.format(mac)))
        self.edit = QLineEdit(current or 'My Computer')
        v.addWidget(self.edit)
        h = QHBoxLayout()
        ok = QPushButton('OK')
        cancel = QPushButton('Cancel')
        h.addStretch(1)
        h.addWidget(ok)
        h.addWidget(cancel)
        v.addLayout(h)
        ok.clicked.connect(self.accept)
        cancel.clicked.connect(self.reject)

    def value(self):
        return self.edit.text().strip()


# ──────────────────────────────────────────────────────────────────────
#  Ping Flooder
# ──────────────────────────────────────────────────────────────────────
FLOOD_PRESETS = [
    ('Rendah (100 pps)', 100),
    ('Sedang (300 pps)', 300),
    ('Tinggi (800 pps)', 800),
    ('Ekstrem (2000 pps)', 2000),
    ('Kustom', -1),
]
FLOOD_SIZES = [
    ('Kecil (56 B)', 56),
    ('Sedang (512 B)', 512),
    ('Besar (1200 B)', 1200),
]


class FloodDialog(QDialog):
    """
    Dialog Ping Flooder: flood ICMP ke host terpilih (bisa massal),
    dengan preset kecepatan + kustom, untuk menaikkan latensi target.
    """

    def __init__(self, parent, hosts):
        super().__init__(parent)
        self.hosts = hosts
        self._timer = QTimer(self)
        self._timer.setInterval(1000)
        self._timer.timeout.connect(self._poll_status)

        self.setWindowTitle('Ping Flooder')
        self.setMinimumSize(520, 540)

        v = QVBoxLayout(self)

        # ---- intensitas ----
        box1 = QGroupBox('Intensitas (paket ICMP per detik)')
        f1 = QFormLayout(box1)
        self.preset = QComboBox()
        for label, _ in FLOOD_PRESETS:
            self.preset.addItem(label)
        self.preset.setCurrentIndex(1)          # Sedang default
        self.preset.currentIndexChanged.connect(self._on_preset)
        f1.addRow('Preset:', self.preset)

        self.spin_hz = QSpinBox()
        self.spin_hz.setRange(1, 5000)
        self.spin_hz.setValue(300)
        self.spin_hz.setSuffix(' pps')
        f1.addRow('Kustom pps:', self.spin_hz)
        v.addWidget(box1)

        # ---- ukuran paket ----
        box2 = QGroupBox('Ukuran paket')
        f2 = QFormLayout(box2)
        self.size = QComboBox()
        for label, _ in FLOOD_SIZES:
            self.size.addItem(label)
        self.size.setCurrentIndex(0)
        f2.addRow('Ukuran:', self.size)
        v.addWidget(box2)

        # ---- daftar host ----
        v.addWidget(QLabel('Pilih host yang AKAN DI-FLOOD (centang):'))
        area = QScrollArea()
        area.setWidgetResizable(True)
        inner = QWidget()
        from PyQt5.QtWidgets import QVBoxLayout as _V
        lay = _V(inner)
        area.setWidget(inner)
        v.addWidget(area, 1)

        self.checkboxes = {}
        for h in hosts:
            hname = h.get('hostname', '') or ''
            is_gw = ('(GATEWAY)' in hname)
            label = '{}   {}'.format(h['ip'], hname)
            cb = QCheckBox(label)
            if is_gw:
                cb.setChecked(False)
                cb.setEnabled(False)     # gateway jangan di-flood
            else:
                cb.setChecked(False)     # default: pilih manual
            self.checkboxes[h['ip']] = cb
            lay.addWidget(cb)
        lay.addStretch(1)

        h = QHBoxLayout()
        b_all = QPushButton('Centang Semua')
        b_none = QPushButton('Kosongkan')
        h.addWidget(b_all)
        h.addWidget(b_none)
        h.addStretch(1)
        v.addLayout(h)

        # ---- tombol aksi ----
        h2 = QHBoxLayout()
        self.btn_start = QPushButton('Start Flood')
        self.btn_stop = QPushButton('Stop Flood')
        self.btn_stop_all = QPushButton('Stop Semua')
        self.btn_close = QPushButton('Close')
        h2.addWidget(self.btn_start)
        h2.addWidget(self.btn_stop)
        h2.addWidget(self.btn_stop_all)
        h2.addStretch(1)
        h2.addWidget(self.btn_close)
        v.addLayout(h2)

        self.status = QLabel('')
        v.addWidget(self.status)

        b_all.clicked.connect(self._check_all)
        b_none.clicked.connect(self._uncheck_all)
        self.btn_start.clicked.connect(self._start)
        self.btn_stop.clicked.connect(self._stop)
        self.btn_stop_all.clicked.connect(self._stop_all)
        self.btn_close.clicked.connect(self._close)

        self._timer.start()

    # ---- helpers ----
    def _on_preset(self, idx):
        _, val = FLOOD_PRESETS[idx]
        if val > 0:
            self.spin_hz.setValue(val)
            self.spin_hz.setEnabled(False)
        else:
            self.spin_hz.setEnabled(True)

    def _check_all(self):
        for cb in self.checkboxes.values():
            if cb.isEnabled():
                cb.setChecked(True)

    def _uncheck_all(self):
        for cb in self.checkboxes.values():
            if cb.isEnabled():
                cb.setChecked(False)

    def _selected_hosts(self):
        return [h for h in self.hosts
                if self.checkboxes.get(h['ip']) and
                self.checkboxes[h['ip']].isChecked()]

    def _hz_size(self):
        return self.spin_hz.value(), FLOOD_SIZES[self.size.currentIndex()][1]

    # ---- aksi ----
    def _start(self):
        targets = self._selected_hosts()
        if not targets:
            self.status.setText('Pilih minimal satu host.')
            return
        hz, size = self._hz_size()
        self.btn_start.setEnabled(False)
        self.status.setText('Memulai flood ke {} host ({} pps)...'.format(
            len(targets), hz))
        try:
            res = api.ping_flood_all(self.hosts, [t['ip'] for t in targets],
                                     hz, size)
            if res.get('status') == 'success':
                done = res.get('done', [])
                if self.parent():
                    self.parent().notify_flooding(done)
                self.status.setText(
                    'FLOOD AKTIF: {} host @ {} pps, {} B'.format(
                        len(done), hz, size))
            else:
                self.status.setText('FAILED: ' + str(res.get('msg', '')))
        except api.ApiError as e:
            self.status.setText('ERROR: {}'.format(e))
        finally:
            self.btn_start.setEnabled(True)

    def _stop(self):
        targets = self._selected_hosts()
        if not targets:
            self.status.setText('Pilih host yang ingin dihentikan.')
            return
        stopped = []
        for h in targets:
            try:
                api.ping_flood_stop(h)
                stopped.append(h['ip'])
            except api.ApiError:
                pass
        if self.parent():
            self.parent().notify_unflooding(stopped)
        self.status.setText('Flood dihentikan: {} host'.format(len(stopped)))

    def _stop_all(self):
        try:
            res = api.ping_flood_stop_all()
            done = res.get('done', [])
            if self.parent():
                self.parent().notify_unflooding(done)
            self.status.setText('Semua flood dihentikan ({} host)'.format(
                len(done)))
        except api.ApiError as e:
            self.status.setText('ERROR: {}'.format(e))

    def _poll_status(self):
        try:
            st = api.ping_flood_status()
        except api.ApiError:
            return
        if not st:
            return
        parts = []
        for ip, info in st.items():
            parts.append('{}: {} pkt'.format(ip, info.get('sent', 0)))
        self.status.setText('FLOOD AKTIF -> ' + ' | '.join(parts))

    def _close(self):
        self._timer.stop()
        self.reject()
