class mac_port_table:
    # This class maintains mapping of MAC addresses to ports for Socket simulation
    def __init__(self):
        self._table = {}  # mac -> (port)

    def add(self, mac, port):
        self._table[mac] = (port)

    def lookup(self, mac):
        return self._table.get(mac)  # Returns port or None

    def all_entries(self):
        return dict(self._table)