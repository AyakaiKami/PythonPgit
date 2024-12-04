#!/usr/bin/python3

import ipaddress
import socket
import struct
import sys
import os
import argparse
import threading
import time


from packet import Ethernet_Frame as Ethernet_Frame
from packet import IP_Packet as IP_Packet
from packet import TCP_Packet as TCP_Packet

from request import Reconstruct as Reconstruct


def sniff(interface):
    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    sniffer.bind((interface,0))

    try:
        while True:
            raw_data=sniffer.recv(65535)
            packet=Ethernet_Frame(raw_data)
            Reconstruct.addPacket(packet)
                
    except KeyboardInterrupt:
        return

if __name__=='__main__':
    if os.getuid()!=0:
        print("This script needs root privilleges to run!")
        sys.exit(1)

    print("Starting Sniffer!")
    
    sniff('wlan0')
    print("Sniffer has been stopped")
