"""Dialog-dialog NetControl (versi PyQt5)."""
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QFormLayout, QLabel, QComboBox,
    QPushButton, QCheckBox, QScrollArea, QWidget, QLineEdit, QMessageBox,
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
