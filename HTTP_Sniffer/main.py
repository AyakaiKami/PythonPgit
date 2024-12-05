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
from tkinter import ttk 
import psutil


from packet import Ethernet_Frame as Ethernet_Frame
from packet import IP_Packet as IP_Packet
from packet import TCP_Packet as TCP_Packet

from request import Reconstruct as Reconstruct

def update_label_size(event):
    # Options bar
    outer_frame_bar_sniffer_options.place(x=0, y=0, width=root.winfo_width(), height=root.winfo_height()//17)
    inner_frame_bar_sniffer_options.place(x=1,y=1,width=root.winfo_width()-2,height=root.winfo_height()//17-2)
    #   Buttons:
    #       -Select interface
    interface_menu.place(x=1,y=1,width=inner_frame_bar_sniffer_options.winfo_width()/16*4,height=inner_frame_bar_sniffer_options.winfo_height()-1)
    #       -Start
    start_button.place(x=inner_frame_bar_sniffer_options.winfo_width()/16*4+1,y=1,width=inner_frame_bar_sniffer_options.winfo_width()/16*2,height=inner_frame_bar_sniffer_options.winfo_height()-1)
    #       -Stop
    stop_button.place(x=inner_frame_bar_sniffer_options.winfo_width()/16*6+1,y=1,width=inner_frame_bar_sniffer_options.winfo_width()/16*2,height=inner_frame_bar_sniffer_options.winfo_height()-1)
    #       -Record Start
    start_recording_button.place(x=inner_frame_bar_sniffer_options.winfo_width()/16*8+1,y=1,width=inner_frame_bar_sniffer_options.winfo_width()/16*4-1,height=inner_frame_bar_sniffer_options.winfo_height()-1)
    #       -Record Stop
    stop_recording_button.place(x=inner_frame_bar_sniffer_options.winfo_width()/16*12+1,y=1,width=inner_frame_bar_sniffer_options.winfo_width()/16*4-1,height=inner_frame_bar_sniffer_options.winfo_height()-1)

    # Left panel
    outer_frame_left_panel.place(x=0,y=root.winfo_height()//17,width=(root.winfo_width()//2),height=(root.winfo_height()//17 * 16))
    inner_frame_left_panel.place(x=1,y=0,width=(root.winfo_width()//2-2),height=(root.winfo_height()//17 * 16-1))
    #   Requests list
    outer_frame_requests_list.place(x=0,y=0,width=inner_frame_left_panel.winfo_width(),height=inner_frame_left_panel.winfo_height()//8 * 3)
    inner_frame_requests_list.place(x=1,y=0,width=outer_frame_requests_list.winfo_width()-1,height=(outer_frame_requests_list.winfo_height()-1))

    frame_filters_list.place(x=1,y=inner_frame_left_panel.winfo_height()//8 * 3,width=inner_frame_left_panel.winfo_width(),height=inner_frame_left_panel.winfo_height()//8 * 5)
    
    #   Request filters
    #       IP filter
    ip_source_label.place(x=0,y=0)

    #       Port Filter
    #       Header filter
    #       Content filter

    # Right panel
    outer_frame_right_panel.place(x=(root.winfo_width()//2),y=root.winfo_height()//17,width=(root.winfo_width()//2),height=(root.winfo_height()//17 * 16))
    inner_frame_right_panel.place(x=0,y=0,width=(root.winfo_width()//2-1),height=(root.winfo_height()//17 * 16-1))


requests_list=[]
is_recording=False

def sniff(interface):
    global requests_list
    global is_recording
    requests_list=[]
    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    sniffer.bind((interface,0))

    print(f"Started sniffing on {interface}")

    try:
        while not stop_thread_event.is_set():
            raw_data=sniffer.recv(65535)
            packet=Ethernet_Frame(raw_data)
            Reconstruct.addPacket(packet)
            if Reconstruct.getLastRequest()!=None:
                if requests_list!=[]:
                    if requests_list[-1]!=Reconstruct.getLastRequest():
                        requests_list.append(Reconstruct.getLastRequest())
                else:
                    requests_list.append(Reconstruct.getLastRequest())
    except Exception as e:
        print(e)
    


if os.getuid()!=0:
    root = Tk()
    root.configure(bg="black")
    root.title('HTTP Sniffer')
    label_error_not_root=Label(root,text="You need need root privileges to run this program!",bg="black",fg="white")
    label_error_not_root.pack(pady=10,padx=10)
    root.mainloop()
    sys.exit(1)


#sniff('wlan0')
root = Tk()
root.geometry(f"{1200}x{800}+{int(root.winfo_screenwidth()/2)-600}+{int(root.winfo_screenheight()/2)-400}")
root.configure(bg="black")
root.title('HTTP Sniffer') # Change name

# Options bar
outer_frame_bar_sniffer_options=Frame(root,bg='white',relief='solid')
inner_frame_bar_sniffer_options=Frame(outer_frame_bar_sniffer_options,bg='black',relief='solid')
#   Buttons:
#       -Select interface
interfaces_list=list(psutil.net_if_addrs().keys())
selected_interface=StringVar(outer_frame_bar_sniffer_options)
selected_interface.set('Select an interface')

interface_menu=OptionMenu(outer_frame_bar_sniffer_options,selected_interface,*interfaces_list)


#       -Start
stop_thread_event=threading.Event()
thread_sniff=None
def start_button_function():
#    print(f"Started sniffing on {selected_interface.get()}")
    global thread_sniff
    if selected_interface!='Select an interface':
        if thread_sniff is None:
            thread_sniff=threading.Thread(target=sniff,args=(selected_interface.get(),))
            thread_sniff.start()
start_button=Button(outer_frame_bar_sniffer_options,text="Start",command=start_button_function)

#       -Stop
def stop_button_function():
    global thread_sniff
    stop_thread_event.set()
    thread_sniff.join()
    stop_thread_event.clear()
    thread_sniff=None
    print(f"Stopped sniffing")


stop_button=Button(outer_frame_bar_sniffer_options,text="Stop",command=stop_button_function)

#       -Record Start
def start_recording():
    print("Recording")
    global is_recording
    is_recording=True
start_recording_button=Button(outer_frame_bar_sniffer_options,text="Start Recording",command=start_recording)

#       -Record Stop
def stop_recording():
    print("Stopped Recording")
    global is_recording
    is_recording=False

stop_recording_button=Button(outer_frame_bar_sniffer_options,text="Stop Recording",command=stop_recording)


# Left Panel
outer_frame_left_panel=Frame(root,bg='white',relief='solid')
inner_frame_left_panel=Frame(outer_frame_left_panel,bg='black',relief='solid')
#   Requests list
outer_frame_requests_list=Frame(inner_frame_left_panel,bg='white',relief='solid')
inner_frame_requests_list=Frame(outer_frame_requests_list,bg='black',relief='solid')

#   Request filters
frame_filters_list=Frame(inner_frame_left_panel,bg='black',relief='solid')
#       IP filter
#           Source
ip_source_label=Label(frame_filters_list,text="Source IP:",bg='black',fg='white',relief='solid')
#           Destination
#       Port Filter
#       Header filter
#       Content filter

# Right Panel
outer_frame_right_panel=Frame(root,bg='white',relief='solid')
inner_frame_right_panel=Frame(outer_frame_right_panel,bg='black',relief='solid')

#   Display Selected request

root.bind('<Configure>',update_label_size)

root.mainloop()
sys.exit(0)

