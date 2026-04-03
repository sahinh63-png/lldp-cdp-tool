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
                row = []
                for c in range(5):
                    item = self.table.item(r, c)
                    row.append(item.text() if item else "")
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
            switch = value.decode(errors="ignore")

        elif tlv_type == 2:
            port = value[1:].decode(errors="ignore")

        elif tlv_type == 8:
            try:
                ip = ".".join(map(str, value[-4:]))
            except:
                pass

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

    if b"Device-ID" in data:
        try:
            switch = data.split(b"Device-ID")[1].split(b"\x00")[1].decode()
        except:
            pass

    if b"Port-ID" in data:
        try:
            port = data.split(b"Port-ID")[1].split(b"\x00")[1].decode()
        except:
            pass

    if b"\x0a\x00" in data:
        idx = data.find(b"\x0a\x00")
        vlan = str(int.from_bytes(data[idx+2:idx+4], "big"))

    if b"\x01\x00" in data:
        idx = data.find(b"\x01\x00")
        ip = ".".join(map(str, data[idx+4:idx+8]))

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
