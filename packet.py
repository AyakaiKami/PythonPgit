import struct
import ipaddress
import socket


class Ethernet_Frame:
    def __init__(self, data) -> None:
        header = struct.unpack('! 6s 6s H', data[:14])
        self.destination_address = Ethernet_Frame.getmac(header[0])
        self.source_address = Ethernet_Frame.getmac(header[1])
        self.type = socket.htons(header[2])

        self.ip_packet = IP_Packet(data[14:])

        self.is_tcp_packet = False
        if self.ip_packet.is_tcp_packet:
            self.is_tcp_packet = True

            # Source
            self.source_ip = self.ip_packet.source_ip
            self.source_port = self.ip_packet.tcp_packet.source_port

            # Destination
            self.destination_ip = self.ip_packet.destination_ip
            self.destination_port = self.ip_packet.tcp_packet.destination_port

            # Sequence number
            self.sequence_number = self.ip_packet.tcp_packet.sequence_number

            # Payload
            self.payload = self.ip_packet.tcp_packet.payload

    @staticmethod
    def getmac(mac):
        return (':'.join(map('{:02x}'.format, mac))).upper()


class IP_Packet:
    def __init__(self, data) -> None:
        header = struct.unpack('! B B H H H B B H 4s 4s', data[:20])
        self.version = header[0] >> 4
        self.header_length = (header[0] & 0xF) * 4
        self.type_of_service = header[1]
        self.length = header[2]

        self.id = header[3]
        self.flags = header[4] >> 13
        self.fragment_offset = header[4] & 0x1FFF

        self.ttl = header[5]
        self.protocol = header[6]
        self.header_checksum = hex(header[7])

        self.source_ip = ipaddress.ip_address(header[8])
        self.destination_ip = ipaddress.ip_address(header[9])

        self.is_tcp_packet = False
        if self.protocol == 6:
            self.is_tcp_packet = True
            self.payload = data[self.header_length:]
            self.tcp_packet = TCP_Packet(self.payload)
            self.application_level_type = self.tcp_packet.type
        else:
            self.payload = None
            self.tcp_packet = None
            self.application_level_type = None

    def __str__(self) -> str:
        buffer = f"Packet from {self.source_ip}:{self.tcp_packet.source_port}"
        buffer += f"to {self.destination_ip}:"
        buffer += f"{self.tcp_packet.destination_port} "
        buffer += f"Sequence_number: {self.tcp_packet.sequence_number}"
        return buffer


class TCP_Packet:
    def __init__(self, data) -> None:
        header = struct.unpack('!HHLLBBHHH', data[:20])
        self.source_port = header[0]
        self.destination_port = header[1]

        self.sequence_number = header[2]
        self.acknowledgment_number = hex(header[3])

        self.data_offset = (header[4] >> 4) * 4
        self.window = header[5]
        self.checksum = header[6]
        self.urgent_pointer = header[7]
        self.payload = ""

        try:
            self.payload = data[self.data_offset:].decode()
        except Exception:
            pass

        self.type = "HTTP" if "HTTP" in self.payload else None

    def __str__(self) -> str:
        return self.payload or "No payload"
