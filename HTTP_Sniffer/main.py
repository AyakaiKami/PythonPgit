#!/usr/bin/python3

import ipaddress
import socket
import struct
import sys
import os
import argparse





if __name__=='__main__':
    if os.getuid()!=0:
        print("This script needs root privilleges to run!")
        sys.exit(1)

    print("Starting Sniffer!")
