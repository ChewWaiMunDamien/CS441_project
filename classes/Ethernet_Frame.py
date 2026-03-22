class E_Frame:
    def __init__(self, destination_mac, source_mac, data):
        self.destination_mac = destination_mac
        self.source_mac = source_mac
        self.data_length = data.length
        self.data = data