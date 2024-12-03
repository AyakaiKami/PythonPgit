#!/usr/bin/python3

import ipaddress
import socket
import struct
import sys
import os
import argparse

from packet import IP_Packet as IP_Packet
from packet import TCP_Packet as TCP_Packet
 

def sniff(host):
    sniffer=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_TCP)
    sniffer.bind((host,0))
    sniffer.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)

    try:
        while True:
            raw_data=sniffer.recv(65535)
            packet=IP_Packet(raw_data)
            print(packet)
    except KeyboardInterrupt:
        return

if __name__=='__main__':
    if os.getuid()!=0:
        print("This script needs root privilleges to run!")
        sys.exit(1)

    print("Starting Sniffer!")
    sniff("192.168.1.130")
    print("Sniffer has been stopped")