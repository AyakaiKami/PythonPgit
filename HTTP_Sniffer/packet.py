import struct 
import ipaddress

class IP_Packet:
    def __init__(self,data) -> None:
        header=struct.unpack('<BBHHHBBH4s4s',data[:(ord(data[0]) & 0xF) * 4])
        self.version=header[0] >> 4
        self.header_length=(header[0]& 0xF)*4
        self.type_of_service=header[1]
        self.length=header[2]
        
        self.id=header[3] 
        self.flags=header[4] >> 13
        self.fragment_offset=header[4]& 0x1FFF
        
        self.ttl=header[5]
        self.protocol=header[6]
        self.header_checksum=hex(header[7])
        
        self.source_ip=ipaddress.ip_address(header[8])
        
        self.destination_ip=ipaddress.ip_address(header[9])

        self.payload=data[(ord(data[0]) & 0xF) * 4:]
        self.tcp_packet=TCP_Packet(self.payload)

    def __str__(self) -> str:
        return f"Packet from {self.source_ip} to {self.destination_ip} Fragment_offset:{self.fragment_offset}"

class TCP_Packet:
    def __init__(self,data) -> None:
        header=struct.unpack('!HHLLBBHHH',data[:20])
        self.source_port=header[0]
        self.destination_port=header[1]
        
        self.sequence_number=header[2]
        
        self.acknowledgment_number=hex(header[3])

        self.window=header[6]

        self.checksum=header[7]
        self.urgent_pointer=header[8]
        
    def __str__(self) -> str:
        return 