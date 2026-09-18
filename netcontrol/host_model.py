"""
Model tabel untuk daftar host (QAbstractTableModel).

Kolom: [Status-icon, IP, MAC, Hostname, IPv6, Status, Alias]
"""
from PyQt5.QtCore import QAbstractTableModel, QModelIndex, Qt
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QApplication, QStyle

COL_ICON = 0
COL_IP = 1
COL_MAC = 2
COL_HOSTNAME = 3
COL_IPV6 = 4
COL_STATUS = 5
COL_ALIAS = 6

HEADERS = ['', 'IP Address', 'MAC Address', 'Hostname', 'IPv6', 'Status', 'Alias']


class HostModel(QAbstractTableModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._rows = []            # list of dict {ip,mac,hostname,ipv6,status,alias}
        self._offline = set()      # ip yang sedang di-cut
        self._limited = {}         # {ip: label}
        self._online_icon = None
        self._offline_icon = None

    # ── ikon ──────────────────────────────────────────────────────
    def _icons(self):
        if self._online_icon is None:
            st = QApplication.style()
            self._online_icon = st.standardIcon(QStyle.SP_DialogApplyButton)
            self._offline_icon = st.standardIcon(QStyle.SP_DialogCancelButton)
        return self._online_icon, self._offline_icon

    # ── QAbstractTableModel ───────────────────────────────────────
    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent=QModelIndex()):
        return len(HEADERS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return HEADERS[section]
        return None

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        row = self._rows[index.row()]
        col = index.column()

        if role == Qt.DisplayRole:
            return {
                COL_ICON: '',
                COL_IP: row['ip'],
                COL_MAC: row['mac'],
                COL_HOSTNAME: row['hostname'],
                COL_IPV6: row['ipv6'],
                COL_STATUS: row['status'],
                COL_ALIAS: row['alias'],
            }.get(col, '')

        if role == Qt.DecorationRole and col == COL_ICON:
            online, offline = self._icons()
            return offline if row['ip'] in self._offline else online

        if role == Qt.TextAlignmentRole and col in (COL_ICON, COL_STATUS):
            return int(Qt.AlignCenter)

        if role == Qt.ToolTipRole:
            return '{}\n{}\n{}'.format(row['ip'], row['mac'], row['hostname'])

        return None

    # ── manajemen state ───────────────────────────────────────────
    def set_hosts(self, hosts):
        self.beginResetModel()
        self._rows = []
        for h in hosts:
            ip = h.get('ip', '')
            self._rows.append({
                'ip': ip,
                'mac': h.get('mac', ''),
                'hostname': h.get('hostname', ''),
                'ipv6': h.get('ipv6', '') or '',
                'status': self._status_for(ip),
                'alias': h.get('alias', ''),
            })
        self.endResetModel()

    def update_statuses(self):
        """Perbarui kolom status & ikon TANPA reset model.

        Memakai dataChanged supaya seleksi baris di tabel tidak hilang
        (beginResetModel akan menghapus seleksi — bikin toggle cut/resume
         di UI gagal karena host terpilih jadi tidak ada).
        """
        if not self._rows:
            return
        for i, r in enumerate(self._rows):
            r['status'] = self._status_for(r['ip'])
        top = self.index(0, 0)
        bottom = self.index(len(self._rows) - 1, self.columnCount() - 1)
        self.dataChanged.emit(top, bottom, [Qt.DisplayRole, Qt.DecorationRole])

    def _status_for(self, ip):
        if ip in self._offline:
            return 'CUT (offline)'
        if ip in self._limited:
            return 'LIMIT: {}'.format(self._limited[ip])
        return 'online'

    def mark_cut(self, ip):
        self._offline.add(ip)
        self._limited.pop(ip, None)
        self.update_statuses()

    def mark_online(self, ip):
        self._offline.discard(ip)
        self._limited.pop(ip, None)
        self.update_statuses()

    def mark_limited(self, ip, label):
        if ip not in self._offline:
            self._limited[ip] = label
        self.update_statuses()

    def mark_unlimited(self, ip):
        self._limited.pop(ip, None)
        self.update_statuses()

    def set_alias(self, ip, alias):
        for r in self._rows:
            if r['ip'] == ip:
                r['alias'] = alias
        self.update_statuses()

    def is_cut(self, ip):
        return ip in self._offline

    def is_limited(self, ip):
        return ip in self._limited

    def cut_ips(self):
        return set(self._offline)

    def limited_ips(self):
        return set(self._limited.keys())

    def host_at(self, row):
        if 0 <= row < len(self._rows):
            return dict(self._rows[row])
        return None

    def all_hosts(self):
        return [dict(r) for r in self._rows]
