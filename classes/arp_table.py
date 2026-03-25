class arp_table:
    #This class holds each node and router's ARP table, which is a mapping of IP addresses to MAC addresses
    #Used to define the subnets
    def __init__(self):
        self._table = {}  # ip -> (mac)

    def add(self, ip, mac):
        self._table[ip] = (mac)

    def lookup(self, ip):
        return self._table.get(ip)  # Returns mac or None

    def all_entries(self):
        return {hex(ip): mac for ip, mac in self._table.items()}