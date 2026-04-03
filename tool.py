import sys
import struct
from scapy.all import sniff
from scapy.layers.l2 import Ether
from PyQt5.QtWidgets import *
from datetime import datetime

seen = set()

class App(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("LLDP/CDP PRO Discovery Tool")
        self.setGeometry(200, 200, 900, 500)

        layout = QVBoxLayout()
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Switch", "IP", "Port", "VLAN", "Time"])

        btn = QPushButton("Export CSV")
        btn.clicked.connect(self.export_csv)

        layout.addWidget(self.table)
        layout.addWidget(btn)
        self.setLayout(layout)

    def add_row(self, sw, ip, port, vlan):
        if not port:
            port = "Unknown"
        key = (sw, ip, port, vlan)
        if key in seen:
            return
        seen.add(key)

        row = self.table.rowCount()
        self.table.insertRow(row)
        self.table.setItem(row, 0, QTableWidgetItem(sw))
        self.table.setItem(row, 1, QTableWidgetItem(ip))
        self.table.setItem(row, 2, QTableWidgetItem(port))
        self.table.setItem(row, 3, QTableWidgetItem(vlan))
        self.table.setItem(row, 4, QTableWidgetItem(datetime.now().strftime("%H:%M:%S")))

    def export_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save CSV", "", "CSV Files (*.csv)")
        if not path:
            return
        with open(path, "w") as f:
            f.write("Switch,IP,Port,VLAN,Time\n")
            for r in range(self.table.rowCount()):
                row = [self.table.item(r, c).text() if self.table.item(r, c) else "" for c in range(5)]
                f.write(",".join(row) + "\n")


def parse_lldp(pkt):
    data = bytes(pkt)
    i = 14
    switch = "-"
    port = "-"
    vlan = "-"
    ip = "-"

    while i < len(data):
        if i + 2 > len(data):
            break
        tlv_header = struct.unpack("!H", data[i:i+2])[0]
        tlv_type = (tlv_header >> 9) & 0x7F
        tlv_len = tlv_header & 0x1FF
        value = data[i+2:i+2+tlv_len]

        if tlv_type == 5:
            try: switch = value.decode(errors="ignore")
            except: switch = str(value)
        elif tlv_type == 2:  # Port-ID
            try: port = value.decode(errors="ignore")
            except: port = str(value)
        elif tlv_type == 8:
            try: ip = ".".join(map(str, value[-4:]))
            except: pass
        elif tlv_type == 127:
            if b"\x00\x80\xc2" in value:
                vlan = str(int.from_bytes(value[-2:], "big"))
        i += 2 + tlv_len

    return switch, ip, port, vlan


def parse_cdp(pkt):
    data = bytes(pkt)
    switch = "-"
    port = "-"
    vlan = "-"
    ip = "-"

    try:
        if b"Device-ID" in data:
            idx = data.find(b"Device-ID") + len(b"Device-ID")
            switch_raw = data[idx:idx+20]
            switch = ''.join([chr(b) for b in switch_raw if 32 <= b <= 126])
    except: switch = "-"
    try:
        if b"Port-ID" in data:
            idx = data.find(b"Port-ID") + len(b"Port-ID")
            port_raw = data[idx:idx+20]
            port = ''.join([chr(b) for b in port_raw if 32 <= b <= 126])
    except: port = "-"
    try:
        if b"\x0a\x00" in data:
            idx = data.find(b"\x0a\x00")
            vlan = str(int.from_bytes(data[idx+2:idx+4], "big"))
    except: vlan = "-"
    try:
        if b"\x01\x00" in data:
            idx = data.find(b"\x01\x00")
            ip = ".".join(map(str, data[idx+4:idx+8]))
    except: ip = "-"

    return switch, ip, port, vlan


def sniff_thread(gui):
    def handler(pkt):
        if pkt.haslayer(Ether):
            if pkt.type == 0x88cc:  # LLDP
                sw, ip, port, vlan = parse_lldp(pkt)
                gui.add_row(sw, ip, port, vlan)
            elif pkt.type == 0x2000:  # CDP
                sw, ip, port, vlan = parse_cdp(pkt)
                gui.add_row(sw, ip, port, vlan)
    sniff(prn=handler, store=0)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = App()
    window.show()

    import threading
    t = threading.Thread(target=sniff_thread, args=(window,), daemon=True)
    t.start()

    sys.exit(app.exec_())
