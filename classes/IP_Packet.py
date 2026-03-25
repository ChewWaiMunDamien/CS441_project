import json

class IP_Packet:
    # Consts for protocols
    PROTOCOL_PING = 1
    PROTOCOL_PING_ECHO = 2

    def __init__(self, destination_IP, source_IP, protocol, payload):
        self.destination_IP = destination_IP
        self.source_IP = source_IP
        self.protocol = protocol
        self.data_length = len(payload) + 4 # 4 bytes for the header (src,dst, protocol, data_length)
        self.payload = payload

    def __len__(self):
        return self.data_length
    
    def __str__(self):
        return (
            f"┌─ IP Packet Header───────────────────────────\n"
            f"│  Src IP   : {hex(self.source_IP)}\n"
            f"│  Dst IP   : {hex(self.destination_IP)}\n"
            f"│  Protocol : {self.protocol}\n"
            f"│  Length   : {self.data_length} bytes\n"
            f"└────────────────────────────────────────"
        )

    def encapsulate(self) -> str:
        return json.dumps({
            "src_ip":   self.source_IP,       # must be "src_ip"
            "dst_ip":   self.destination_IP,  # must be "dst_ip"
            "protocol": self.protocol,
            "payload":  self.payload,
            "data_length": self.data_length,
        })

    @classmethod
    def deEncapsulate(cls, raw: str) -> "IP_Packet":
        # For deserialize, packet from json string
        raw_data = json.loads(raw)
        return cls(raw_data["dst_ip"], raw_data["src_ip"], raw_data["protocol"], raw_data["payload"])