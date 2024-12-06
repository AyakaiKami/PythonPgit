#!/usr/bin/python3

import socket
import sys
import os
import argparse
from datetime import datetime
import json

from packet import Ethernet_Frame
from request import Request, Reconstruct

interface = None
source_ip = None
destination_ip = None
source_port = None
destination_port = None
type_request = None
headers = None
content = None
record = False
verbose = False

file_path = None


def sniff(interface):
    """
    Sniffs packets from a specified interface

    Args:
        interface (str): The network interface
        to sniff on (e.g., wlan0, eth0, etc.)
    """
    try:
        sniffer = socket.socket(socket.AF_PACKET,
                                socket.SOCK_RAW, socket.ntohs(0x0003))
        sniffer.bind((interface, 0))
        sniffer.settimeout(1)

        print(f"Started sniffing on {interface}")

        while True:
            try:
                raw_data = sniffer.recv(65535)
                packet = Ethernet_Frame(raw_data)
                Reconstruct.addPacket(packet)
                if Reconstruct.getLastRequest() is not None:
                    if filterRequest(Reconstruct.getLastRequest()):

                        if verbose:
                            Reconstruct.getLastRequest().print_verbose()
                        else:
                            Reconstruct.getLastRequest().print_simple()

                        if record:
                            record_request(Reconstruct.getLastRequest())
                        Reconstruct.loseAll()

            except socket.timeout:
                continue
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"Error: {e}")
    except Exception as e:
        print(f"Loop error: {e}")
    finally:
        sniffer.close()
        print("Stopped sniffing")


def parse_arguments():
    """
    Parses and processes command-line arguments.

    Sets global variables based on the parsed arguments.
    """
    global source_ip
    global destination_ip
    global source_port
    global destination_port
    global type_request
    global headers
    global content
    global record
    global interface
    global verbose

    parser = argparse.ArgumentParser(
        description="HTTP Sniffer Arguments Parser")

    parser.add_argument(
        "--interface", type=str, required=True,
        help="Network interface to sniff on (e.g., wlan0, eth0)\n")
    parser.add_argument("--source_ip", type=str,
                        help="Source IP address to filter packets\n")
    parser.add_argument("--destination_ip", type=str,
                        help="Destination IP address to filter packets\n")
    parser.add_argument("--source_port", type=int,
                        help="Source port to filter packets\n")
    parser.add_argument("--destination_port", type=int,
                        help="Destination port to filter packets\n")
    parser.add_argument("--type_request", type=str,
                        help="Type of request (e.g., GET, POST)\n")
    parser.add_argument(
        "--headers", type=str, nargs="*",
        help="List of header keys and values (key1:value1 key2:value2)\n")
    parser.add_argument("--content", type=str,
                        help="Content to filter in the packet\n")
    parser.add_argument("--record", action="store_true",
                        help="Flag to start recording traffic\n")
    parser.add_argument("--verbose", action="store_true",
                        help="Flag to display payloads\n")

    args = parser.parse_args()

    headers_dict = {}
    if args.headers:
        for header in args.headers:
            key, _, value = header.partition(":")
            headers_dict[key.strip()] = value.strip()

    if args.interface is not None:
        interface = args.interface
    if args.source_ip is not None:
        source_ip = args.source_ip
    if args.destination_ip is not None:
        destination_ip = args.destination_ip
    if args.source_port is not None:
        source_port = args.source_port
    if args.destination_port is not None:
        destination_port = args.destination_port
    if args.type_request is not None:
        type_request = args.type_request.upper()
    if headers_dict is not None:
        headers = headers_dict
    if args.content is not None:
        content = args.content
    if args.record is not None:
        record = args.record
    if args.verbose is not None:
        verbose = args.verbose


def filterRequest(request: Request):
    """
    Filters requests based on user-defined criteria.

    Args:
        request (Request): The HTTP request
        to evaluate against the filter criteria.

    Returns:
        bool: True if the request matches the filter criteria, False otherwise.
    """
    if source_ip is not None and request.source_ip != source_ip:
        return False
    if source_port is not None and request.source_port != source_port:
        return False

    if destination_ip is not None and request.destination_ip != destination_ip:
        return False
    if destination_port is not None:
        if request.destination_port != destination_port:
            return False

    if type_request and not request.request_line.startswith("HTTP"):
        if not request.request_line.startswith(type_request):
            return False

    for header_key, header_value in headers.items():
        if not request.header_fields.get(header_key):
            return False
        else:
            if request.header_fields[header_key] != header_value:
                return False

    if content:
        if request.content:
            if content not in request.content:
                return False
        else:
            return False

    return True


def record_request(request: Request) -> None:
    """
    Records the given HTTP request to a JSON file.

    Args:
        request (Request): The HTTP request to be recorded.
    """

    global file_path

    if not file_path:
        file_path = "requests_capture_"
        file_path += f"{datetime.now().strftime('%d %m %Y %H %M %S')}.json"
        with open(file_path, "w") as f:
            f.write('[]')

    request_dict = {
        "source_ip": request.source_ip,
        "source_port": request.source_port,
        "destination_ip": request.destination_ip,
        "destination_port": request.destination_port,
        "request_line": request.request_line,
        "header_fields": request.header_fields,
        "content": request.content,
    }

    with open(file_path, "r+") as f:
        data = json.load(f)
        data.append(request_dict)
        f.seek(0)
        json.dump(data, f, indent=2)


if __name__ == '__main__':
    """
    Entry point for the program.

    Checks for root privileges and
    starts packet sniffing on the specified interface.
    """
    if os.getuid() != 0:
        print("You need root privileges to run this program!")
        sys.exit(1)

    parse_arguments()

    if interface is not None:
        sniff(interface)
