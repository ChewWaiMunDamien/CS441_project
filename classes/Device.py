import socket
import json

class Device:
    def __init__(self,name,ip,mac, port=12345):
        self.name = name
        self.ip = ip
        self.mac = mac
        self.port = port

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.bind(('', port))

    def send_frame(self,dest_mac,payload):
        frame = E_Frame(dest_mac,self.mac,payload)
        self.socket.sendto(json.dumps(frame).encode, ('<broadcast>', self.port))
    
    def receive_frame(self):
        print(f"{self.name} is listening for frames.... IP: {self.ip} MAC: {self.mac}")

        while True:
            data,addr = self.sock.recvfrom(1024) #1024 byte buffer


