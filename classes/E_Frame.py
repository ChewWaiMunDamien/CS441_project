import json
from .IP_Packet import IP_Packet

class E_Frame:

    Broadcast_MAC = "FF"

    def __init__(self, dest_mac, src_mac, payload):
        self.dest_mac = dest_mac
        self.src_mac = src_mac
        self.data_length = len(payload)
        self.payload = payload
    
    def __len__(self):
        return self.data_length + 5 # 5 bytes for dest_mac, src_mac, data_length
    
    def __str__(self, receiver_name=""):
        return (
            f"┌─ [{receiver_name}] Ethernet Frame ──────────────────\n"
            f"│  Dst MAC  : {self.dest_mac}\n"
            f"│  Src MAC  : {self.src_mac}\n"
            f"│  Length   : {self.data_length} bytes\n"
            f"└──────────────────────────────────────────"
        )
    
    def encapsulate(self) -> bytes:
        # Convert frame into bytes for Socket UDP transmission
        frame_dict = {
            "dst_mac":     self.dest_mac,
            "src_mac":     self.src_mac,
            "data_length": self.data_length,
            "payload":     self.payload.encapsulate(),  # serialize IP packet into json string for transmission
        }
        return json.dumps(frame_dict).encode("utf-8")

    @classmethod
    def deEncapsulate(cls, raw: bytes) -> "E_Frame":
        # Deserialize frame from bytes received from Socket UDP
        raw_data     = json.loads(raw.decode("utf-8"))
        ip_packet = IP_Packet.deEncapsulate(raw_data["payload"])  # reconstruct nested IP packet into IP packet class
        return cls(raw_data["dst_mac"], raw_data["src_mac"], ip_packet)
