#!/usr/bin/python3

import ipaddress
import socket
import struct
import sys
import os
import argparse
import threading
import time

from packet import *
from request import *

source_ip=None
destination_ip=None
source_port=None
destination_port=None
type_request=None
headers=None
content=None
record=False

interface=None

def sniff(interface):

    try:
        sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        sniffer.bind((interface,0))
        sniffer.settimeout(1)

        print(f"Started sniffing on {interface}")

        while True:
            try:
                raw_data=sniffer.recv(65535)
                packet=Ethernet_Frame(raw_data)
                Reconstruct.addPacket(packet)
                if Reconstruct.getLastRequest()!=None:
                    if filterRequest(Reconstruct.getLastRequest()):
                        print(Reconstruct.getLastRequest())
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
    global source_ip
    global destination_ip
    global source_port
    global destination_port
    global type_request
    global headers
    global content
    global record
    global interface

    parser = argparse.ArgumentParser(description="HTTP Sniffer Arguments Parser")
    
    # Define the arguments
    parser.add_argument("--interface", type=str, required=True, help="Network interface to sniff on (e.g., wlan0, eth0)\n")
    parser.add_argument("--source_ip", type=str, help="Source IP address to filter packets\n")
    parser.add_argument("--destination_ip", type=str, help="Destination IP address to filter packets\n")
    parser.add_argument("--source_port", type=int, help="Source port to filter packets\n")
    parser.add_argument("--destination_port", type=int, help="Destination port to filter packets\n")
    parser.add_argument("--type_request", type=str, help="Type of request (e.g., GET, POST)\n")
    parser.add_argument("--headers", type=str, nargs="*", help="List of header keys and values (e.g., key1:value1 key2:value2)\n")
    parser.add_argument("--content", type=str, help="Content to filter in the packet\n")
    parser.add_argument("--record", action="store_true", help="Flag to start recording traffic\n")
    
    args = parser.parse_args()
    
    headers_dict = {}
    if args.headers:
        for header in args.headers:
            key, _, value = header.partition(":")
            headers_dict[key.strip()] = value.strip()
    
    
    interface = args.interface if args.interface!=None else None
    source_ip = args.source_ip if args.source_ip!=None else None
    destination_ip = args.destination_ip if args.destination_ip!=None else None
    source_port = args.source_port if args.source_port!=None else None
    destination_port = args.destination_port if args.destination_port!=None else None
    type_request = args.type_request.upper() if args.type_request!=None else None
    headers = headers_dict if headers_dict!=None else None
    content = args.content if args.content!=None else None
    record = args.record if args.record!=None else False
    
def filterRequest(request:Request):
    if source_ip!=None and request.source_ip!=source_ip:
        return False
    if source_port!=None and request.source_port!=source_port:
        return False
    
    if destination_ip!=None and request.destination_ip!=destination_ip:
        return False
    if destination_port!=None and request.destination_port!=destination_port:
        return False
    
    
    if type_request and not request.request_line.startswith("HTTP") and not request.request_line.startswith(type_request):
        return False
    
    return True



if os.getuid()!=0:
    print("You need need root privileges to run this program!")
    sys.exit(1)

args=parse_arguments()

if interface!=None:
    sniff(interface)






