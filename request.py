from packet import Ethernet_Frame as Ethernet_Frame


class Reconstruct:
    """
    Handles the reconstruction of HTTP requests from captured packets.
    """

    requests_return_list = []
    requests_list = {}

    @staticmethod
    def addPacket(packet: Ethernet_Frame):
        """
        Processes a packet and attempts to reconstruct an HTTP request.

        Args:
            packet (Ethernet_Frame): The captured Ethernet
            frame containing packet data.
        """
        if packet.is_tcp_packet:
            key = f"{packet.source_ip}:{packet.source_port}"
            key += f" -> {packet.destination_ip}:{packet.destination_port}"

            if Reconstruct.requests_list.get(key) is None:
                if "HTTP" in packet.payload.split('\n')[0]:
                    Reconstruct.requests_list[key] = {
                        'sequence_number': packet.sequence_number,
                        'request': Request(
                            packet.payload, packet.source_ip,
                            packet.source_port, packet.destination_ip,
                            packet.destination_port)
                    }

                    if Reconstruct.requests_list[key]['request'].is_full():
                        Reconstruct.requests_return_list.append(
                            Reconstruct.requests_list[key]['request'])
                        Reconstruct.requests_list[key] = None

            else:
                request_data = Reconstruct.requests_list[key]
                if request_data['sequence_number'] < packet.sequence_number:
                    request_data['sequence_number'] = packet.sequence_number
                    request_data['request'].append(packet.payload)

                    if request_data['request'].is_full():
                        Reconstruct.requests_return_list.append(
                            request_data['request'])
                        Reconstruct.requests_list[key] = None

    @staticmethod
    def getLastRequest():
        """
        Retrieves the last fully reconstructed HTTP request.

        Returns:
            Request or None: The last HTTP request
            if available, None otherwise.
        """
        if Reconstruct.requests_return_list != []:
            return Reconstruct.requests_return_list[-1]
        return None

    @staticmethod
    def loseAll():
        """
        Clears the list of reconstructed HTTP requests.
        """
        Reconstruct.requests_return_list = []


class Request:
    """
    Represents an HTTP request and handles
    its reconstruction from packet payloads.
    """

    def __init__(self, data, source_ip,
                 source_port, destination_ip, destination_port) -> None:
        """
        Initializes the HTTP request object.

        Args:
            data (str): The raw HTTP request payload.
            source_ip (str): Source IP address.
            source_port (int): Source port number.
            destination_ip (str): Destination IP address.
            destination_port (int): Destination port number.
        """
        lines = [line + '\n' for line in data.split('\n')]
        self.request_line = str(lines[0])
        self.source_ip = str(source_ip)
        self.source_port = int(source_port)
        self.destination_ip = str(destination_ip)
        self.destination_port = int(destination_port)
        self.header_fields = {}

        self.is_empty_line_set = False
        self.empty_line = 0

        for i, line in enumerate(lines[1:], 1):
            self.empty_line = i
            if line == "\r\n":
                self.is_empty_line_set = True
                break

            header_key = line.split(':')[0]
            header_value = line.split(':')[1].removeprefix(' ')
            header_value.removesuffix('\n').removesuffix('\r')

            self.header_fields[header_key] = header_value

        self.content = None
        self.is_over = False
        if self.header_fields.get('Content-Length') is not None:
            self.content = "".join(lines[self.empty_line + 1:])
            if len(self.content) == int(self.header_fields['Content-Length']):
                self.is_over = True
        else:
            if self.is_empty_line_set:
                self.is_over = True

    def append(self, data) -> None:
        """
        Appends additional packet payload data to the HTTP request.

        Args:
            data (str): Additional raw HTTP payload.
        """
        lines = [line + '\n' for line in data.split('\n')]

        if not self.is_empty_line_set:
            last_empty_line = self.empty_line
            for i, line in enumerate(lines, last_empty_line + 1):
                self.empty_line = i
                if line == "\r\n":
                    self.is_empty_line_set = True
                    break
                header_key = line.split(':')[0]
                header_value = line.split(':')[1]
                header_value.removeprefix(' ').removesuffix('\n')

                self.header_fields[header_key] = header_value

            self.content = None
            self.is_over = False
            if self.header_fields.get('Content-Length') is not None:
                self.content += "".join(lines[self.empty_line + 1:])
                if len(self.content) == self.header_fields['Content-Length']:
                    self.is_over = True
            else:
                if self.is_empty_line_set:
                    self.is_over = True
        else:
            self.content += "".join(lines)

            if len(self.content) >= int(self.header_fields['Content-Length']):
                self.is_over = True

    def is_full(self):
        """
        Checks if the HTTP request is fully reconstructed.

        Returns:
            bool: True if the request is complete, False otherwise.
        """
        return self.is_over

    def __str__(self) -> str:
        """
        Converts the HTTP request object into a string representation.

        Returns:
            str: The string representation of the HTTP request.
        """
        buffer = f"Request from {self.source_ip}:{self.source_port}"
        buffer += f" to {self.destination_ip}:{self.destination_port}\n"
        buffer += "----------Start Request----------\n"
        buffer += self.request_line
        for key, value in self.header_fields.items():
            buffer += f"{key}: {value}\n"

        buffer += "\n"
        if self.content is not None:
            buffer += self.content
        buffer += "----------End Request-------------\n"
        return buffer

    def print_verbose(self) -> None:
        """
        Prints a detailed representation of the HTTP request to the console.
        """
        buffer = f"Request from {self.source_ip}:{self.source_port}"
        buffer += f"to {self.destination_ip}:{self.destination_port}\n"
        buffer += "----------Start Request----------\n"
        buffer += self.request_line
        for key, value in self.header_fields.items():
            buffer += f"{key}: {value}\n"

        buffer += "\n"
        if self.content is not None:
            buffer += self.content
        buffer += "----------End Request-------------\n"
        print(buffer)

    def print_simple(self) -> None:
        """
        Prints a simplified representation of the HTTP request to the console.
        """
        buffer = f"Request from {self.source_ip}:{self.source_port}"
        buffer += f"to {self.destination_ip}:{self.destination_port}\n"
        buffer += "----------Start Request----------\n"
        buffer += self.request_line
        for key, value in self.header_fields.items():
            buffer += f"{key}: {value}\n"

        buffer += "----------End Request-------------\n"
        print(buffer)
