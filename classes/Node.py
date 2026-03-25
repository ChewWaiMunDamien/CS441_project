import socket, sys
from .E_Frame import E_Frame
from .IP_Packet import IP_Packet

class Node:
    def __init__(self, name, IP, MAC, ARP_Table, MAC_Socket_Table, default_Gateway, port, host):
        self.name = name
        self.IP = IP
        self.MAC = MAC
        self.ARP_Table = ARP_Table
        self.MAC_Socket_Table = MAC_Socket_Table
        self.listening = False
        self.default_Gateway = default_Gateway
        self.host = host
        self.port = port

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((host, port))

    def listen(self):
        print(f"\n[{self.name}] Listening on port {self.port}")  
        while True:
            raw = self.sock.recv(4096) # max buffer size should be max frame size (261) but scared that it would be bigger then expected
            frame = E_Frame.deEncapsulate(raw)
            print(f"\n{frame.__str__(self.name)}")
            self.handle(frame)

    def handle(self,frame):
        # If not destination MAC drop the packet, unless the node is in listening mode
        if (frame.dest_mac == self.MAC or frame.dest_mac == E_Frame.Broadcast_MAC or self.listening):
            packet = frame.payload
            print(f"\n{packet.__str__(self.name)}")
            # If not destination IP drop the packet
            if packet.destination_IP == self.IP:
                if packet.protocol == IP_Packet.PROTOCOL_PING:
                    print(f"[{self.name}] PING from {hex(packet.source_IP)} — sending echo\n")
                    self.send_reply(IP_Packet.PROTOCOL_PING_ECHO, packet.source_IP)
                elif packet.protocol == IP_Packet.PROTOCOL_PING_ECHO:
                     print(f"[{self.name}] PING ECHO from {hex(packet.source_IP)}\n")

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
        try:
            dest_mac = self.get_mac(dest_ip)
            if dest_mac is None:
                print(f"\n{self.name} has no ARP entry or default gateway for {dest_ip}, cannot send reply")
                return

            dest_port = self.get_port(dest_mac)
            print(f"\n[{self.name}] send_packet: dest_port={dest_port}")
            if dest_port is None:
                print(f"\n{self.name} has no MAC-Port entry for {dest_mac}, cannot send reply")
                return

            frame = self.make_frame(packet, dest_mac)
            self.sock.sendto(frame.encapsulate(), (self.host, dest_port))
        except Exception as e:
            print(f"\n{self.name} had error sending packet:", e)

    def parse_string_to_hex(self,s):
        return int(s,16) # Return the string as a hex integer
    
    def send_reply(self,protocol,dest_ip):
        if (type(dest_ip) == str):
            dest_ip = self.parse_string_to_hex(dest_ip)

        payload = ""
        if protocol == IP_Packet.PROTOCOL_PING:
            payload = "Echo Reply"
        elif protocol == IP_Packet.PROTOCOL_PING_ECHO:
            payload = "Ping Echo"

        reply_packet = self.make_packet(payload, dest_ip, protocol)
        self.send_packet(reply_packet, dest_ip)

    def cli(self):
        print(f"\nNode {self.name} | IP: {hex(self.IP)} | MAC: {self.MAC}")
        print("\nCommands: ping <ip> | arp | MAC-Port | back")
        while True:
            cmd = input(f"\n{self.name}> ").strip().split()
            if not cmd: continue
            if cmd[0] == "ping" and len(cmd) == 2:
                self.send_reply(IP_Packet.PROTOCOL_PING, cmd[1])
            elif cmd[0] == "arp":
                print(f"\n{self.ARP_Table.all_entries()}")
            elif cmd[0] == "MAC-Port":
                print(f"\n{self.MAC_Socket_Table.all_entries()}")
            elif cmd[0] == "back":
                break
            else:
                print(f"\nInvalid command. Commands: ping <ip> | arp | MAC-Port | quit")