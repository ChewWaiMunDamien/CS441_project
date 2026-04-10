import socket
from .E_Frame import E_Frame
from .IP_Packet import IP_Packet

class Router:
    def __init__(self, routing_table, broadcast_table, MAC_Socket_Table, ARP_table, interfaces, port, host):
        self.routing_table = routing_table # routing table is prefix to interface mapping, where interface is the interface to send the packet out of
        self.broadcast_table = broadcast_table # dictionary mapping of sockets to each interface for broadcast
        self.ARP_table = ARP_table
        self.interfaces = interfaces # List of interfaces, where each interface has a name, IP and MAC address
        self.MAC_Socket_Table = MAC_Socket_Table

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((host,port))
        self.host = host

    def get_prefix(ip: int) -> int:
        return (ip >> 4) & 0xF    # extract a from 0xabcd, we want to get 0x1, which is the prefix for the LAN

    def route_to_interface(self, packet):
        prefix = Router.get_prefix(packet.destination_IP)
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
                return interface
        return None

    def parse_string_to_hex(self,s):
        return int(s,16) # Return the string as a hex integer

    def listen(self):
        while True:
            raw = self.sock.recv(4096)
            frame = E_Frame.deEncapsulate(raw)
            print(f"\n{frame.__str__('Router')}")
            self.handle(frame)

    def destination_interface(self,frame):
        for i in self.interfaces:
            if i.MAC == frame.dest_mac:
                return i
        return None
                

    def handle(self,frame):
        # If not destination MAC drop the packet, unless the node is in listening mode
        target_interface = next((i for i in self.interfaces if i.MAC == frame.dest_mac), None)
        if (target_interface or frame.dest_mac == E_Frame.Broadcast_MAC):
            packet = frame.payload
            print(f"\n{packet.__str__("Router")}")
            # If not destination IP drop the packet
            destination_interface = self.dest_is_router(packet)
            if destination_interface:
                if packet.protocol == IP_Packet.PROTOCOL_PING:
                    print(f"[{destination_interface.name}] PING from {hex(packet.source_IP)} — sending echo")
                    # Pass the specific interface to send_reply so we use the right source IP
                    self.send_reply(IP_Packet.PROTOCOL_PING_ECHO, packet.source_IP, destination_interface)
                elif packet.protocol == IP_Packet.PROTOCOL_PING_ECHO:
                    print(f"[{destination_interface.name}] PING ECHO from {hex(packet.source_IP)}")
                return
            else:
                self.forward(packet)
        
    def send_reply(self,protocol,dest_ip, src_interface):
        if (type(dest_ip) == str):
            dest_ip = self.parse_string_to_hex(dest_ip)

        payload = ""
        if protocol == IP_Packet.PROTOCOL_PING_ECHO:
            payload = "Ping Echo"

        reply_packet = self.make_packet(payload, src_interface, dest_ip, protocol)
        self.send_packet(reply_packet, dest_ip, src_interface)

    def make_packet(self, payload, src_interface, dest_ip, protocol):
        return IP_Packet(dest_ip, src_interface.IP, protocol, payload)
    
    def make_frame(self, packet, src_interface, dest_mac):
        return E_Frame(dest_mac, src_interface.MAC, packet)

    def get_mac(self, ip):
        mac_entry = self.ARP_table.lookup(ip)
        return mac_entry

    def get_port(self, mac):
        port_entry = self.MAC_Socket_Table.lookup(mac)
        return port_entry

    def send_packet(self, packet, dest_ip, src_interface):
        try:
            dest_mac = self.get_mac(dest_ip)
            if dest_mac is None:
                print(f"\nRouter has no ARP entry for {dest_ip}, cannot send reply")
                return

            dest_port = self.get_port(dest_mac)
            sending_interface = self.route_to_interface(packet)
            print(f"\n[{src_interface.name}] send_packet: dest_port={dest_port}")
            if dest_port is None:
                print(f"\n{src_interface.name} has no MAC-Port entry for {dest_mac}, cannot send reply")
                return

            frame = self.make_frame(packet, sending_interface, dest_mac)
            self.sock.sendto(frame.encapsulate(), (self.host, dest_port))
        except Exception as e:
            print(f"\nRouter had error sending packet:", e)



