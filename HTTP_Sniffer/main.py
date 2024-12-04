#!/usr/bin/python3

import ipaddress
import socket
import struct
import sys
import os
import argparse
import threading
import time
from tkinter import * 
import psutil


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


if os.getuid()!=0:
    print("This script needs root privilleges to run!")
    sys.exit(1)

interfaces_list=list(psutil.net_if_addrs().keys())
    
#sniff('wlan0')
root = Tk()
root.geometry(f"{1200}x{800}+{int(root.winfo_screenwidth()/2)-600}+{int(root.winfo_screenheight()/2)-400}")
root.configure(bg="black")
root.title('HTTP Sniffer') # Change name


label_select_interface=Label(root,text="Select network interface:",bg="black",fg="white")
label_select_interface.pack(pady=10,padx=10)

root.mainloop()

