import socket, sys
from .E_Frame import E_Frame
from .IP_Packet import IP_Packet

class Node:
    def __init__(self, name, IP, MAC, ARP_Table, MAC_Socket_Table, default_Gateway, host, port):
        self.name = name
        self.IP = IP
        self.MAC = MAC
        self.ARP_Table = ARP_Table
        self.MAC_Socket_Table = MAC_Socket_Table
        self.listening = False
        self.default_Gateway = default_Gateway

        self.sock = socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((host, port))

    def listen(self):
        while True:
            raw = self.sock.recv(4096) # max buffer size should be max frame size (261) but scared that it would be bigger then expected
            frame = E_Frame.deEncapsulate(raw)
            print("\n"+frame)
            self.handle(frame)

    def handle(self,frame):
        # If not destination MAC drop the packet, unless the node is in listening mode
        if (frame.dest_mac == self.MAC or frame.dest_mac == E_Frame.Broadcast_MAC or self.listening):
            packet = frame.payload # Should be deEncapsulating here but want to show the whole packet above
            print("\n"+packet)
            # If not destination IP drop the packet, unless the node is in listening mode
            if (packet.destination_IP == self.IP or self.listening):
                if packet.protocol == IP_Packet.PROTOCOL_PING:
                    print(f"\n{self.name} received ping from {packet.source_IP}")
                    self.send_reply(IP_Packet.PROTOCOL_PING, packet.source_IP)
                elif packet.protocol == IP_Packet.PROTOCOL_PING_ECHO:
                    print(f"\n{self.name} received ping echo from {packet.source_IP}")

    def get_mac(self, ip):
        mac_entry = self.ARP_Table.lookup(ip)
        if mac_entry is None:
            return self.default_Gateway
        return mac_entry

    def get_port(self, mac):
        port_entry = self.MAC_Socket_Table.lookup(mac)
        if port_entry is None:
            return None
        return port_entry

    def make_packet(self, payload, dest_ip, protocol):
        return IP_Packet(dest_ip, self.IP, protocol, payload)
    
    def make_frame(self, packet, dest_mac):
        return E_Frame(dest_mac, self.MAC, packet)

    def send_packet(self, packet, dest_ip):
        dest_mac = self.get_mac(dest_ip)
        if dest_mac is None:
            print(f"\n{self.name} has no ARP entry or default gateway for {dest_ip}, cannot send reply")
            return

        dest_port = self.get_port(dest_mac)
        if dest_port is None:
            print(f"\n{self.name} has no MAC-Port entry for {dest_mac}, cannot send reply")
            return

        frame = self.make_frame(packet, dest_mac)
        self.sock.sendto(frame, (self.host, dest_port))

    def send_reply(self,protocol,dest_ip):
        payload = ""
        if protocol == IP_Packet.PROTOCOL_PING:
            payload = "Echo Reply"

        reply_packet = self.make_packet(payload, dest_ip, protocol)
        self.send_packet(reply_packet.encapsulate(), dest_ip)

    def cli(self):
        print(f"\nNode {self.name} | IP: {self.ip} | MAC: {self.mac} | Port: {self.port}")
        print("\nCommands: ping <ip> | arp | MAC-Port | quit")
        while True:
            cmd = input(f"{self.name}> ").strip().split()
            if not cmd: continue
            if cmd[0] == "ping" and len(cmd) == 2:
                self.send_packet("ping", cmd[1])
            elif cmd[0] == "arp":
                print("\n"+self.ARP_Table.all_entries())
            elif cmd[0] == "MAC-Port":
                print("\n"+self.MAC_Socket_Table.all_entries())
            elif cmd[0] == "quit":
                sys.exit(0)