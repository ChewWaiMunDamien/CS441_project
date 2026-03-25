import socket
from .E_Frame import E_Frame

class Router:
    def __init__(self, routing_table, broadcast_table, ARP_table, interfaces, port, host):
        self.routing_table = routing_table # routing table is prefix to interface mapping, where interface is the interface to send the packet out of
        self.broadcast_table = broadcast_table # dictionary mapping of sockets to each interface for broadcast
        self.ARP_table = ARP_table
        self.interfaces = interfaces # List of interfaces, where each interface has a name, IP and MAC address

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((host,port))

    def get_prefix(ip: int) -> int:
        return (ip >> 4) & 0xF    # extract a from 0xabcd, we want to get 0x1, which is the prefix for the LAN

    def route_to_interface(self, packet):
        prefix = Router.get_prefix(packet.destination_IP)
        print(prefix)
        return self.routing_table.get(prefix) # Returns interface to send packets out of, or None if no route
    
    def targets_broadcast(self, interface):
        # Return list of ports to send to using sockets
        return self.broadcast_table.get(interface.name)

    def forward(self, packet):
        interface = self.route_to_interface(packet) # Returns interface to send packets out of

        if interface is None:
            print(f"\nRouter has no route for {hex(packet.destination_IP)}, dropping packet")
            # Should not happen, if happening there is a issue
            return
        
        targets = self.targets_broadcast(interface) # Returns list of ports to send to using sockets

        dst_mac = self.ARP_table.lookup(packet.destination_IP)
        src_mac = interface.MAC

        for target in targets:
            frame = E_Frame(dst_mac, src_mac, packet)
            self.sock.sendto(frame.encapsulate(), target)

    def dest_is_router(self,packet):
        for interface in self.interfaces:
            if packet.destination_IP == interface.IP:
                return True
        return False

    def listen(self):
        while True:
            raw = self.sock.recv(4096)
            frame = E_Frame.deEncapsulate(raw)
            print(f"\n{frame}")
            packet = frame.payload
            print(f"\n{packet}")
            if (self.dest_is_router(packet)):
                continue
            else:
                self.forward(packet)



