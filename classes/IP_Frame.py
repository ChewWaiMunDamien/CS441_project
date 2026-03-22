class IP_Frame:
    def __init__(self, destination_ip, protocol, source_ip, data):
        self.destination_ip = destination_ip
        self.source_ip = source_ip
        self.protocol = protocol
        self.data_length = data.length
        self.data = data