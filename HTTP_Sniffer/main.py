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


def sniff_incoming(host):
    sniffer=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_TCP)
    sniffer.bind((host,0))
    sniffer.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)

    try:
        while True:
            raw_data=sniffer.recv(65535)
            packet=IP_Packet(raw_data)
            #if packet.application_level_type=="HTTP":
            print(packet)
    except KeyboardInterrupt:
        return

def sniff_outgoing(interface):
    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    sniffer.bind((interface,0))

    try:
        while True:
            raw_data=sniffer.recv(65535)
            packet=Ethernet_Frame(raw_data)
            
    except KeyboardInterrupt:
        return

if __name__=='__main__':
    if os.getuid()!=0:
        print("This script needs root privilleges to run!")
        sys.exit(1)

    print("Starting Sniffer!")
    
    t_sniff_incomming=threading.Thread(target=sniff_incoming,args=("192.168.1.130",))
    t_sniff_outgoing=threading.Thread(target=sniff_outgoing,args=("wlan0",))
    
    #t_sniff_incomming.start()
    t_sniff_outgoing.start()

    #t_sniff_incomming.join()
    t_sniff_outgoing.join()
    print("Sniffer has been stopped")
