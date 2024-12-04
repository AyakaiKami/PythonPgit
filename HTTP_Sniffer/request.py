from packet import Ethernet_Frame as Ethernet_Frame

class Requests:
    requests_list={}
    def addPacket(packet:Ethernet_Frame):
        if packet.is_tcp_packet:
            key=f"{packet.source_ip}:{packet.source_port}->{packet.destination_ip}:{packet.destination_port}"
            if Requests.requests_list.get(key) == None:
                if "HTTP" in packet.payload.split('\n')[0]:
                    Requests.requests_list[key]={'sequence_number':packet.sequence_number,'payload':packet.payload}
            else:
                if Requests.requests_list.get(key) != None:
                    if Requests.requests_list[key]['sequence_number']<packet.sequence_number:
                        Requests.requests_list[key]['sequence_number']=packet.sequence_number
                        Requests.requests_list[key]['payload']+=packet.payload

                    if "\r\n" in Requests.requests_list[key]['payload']:
                        print(f"Packet :{packet.source_ip}:{packet.source_port}->{packet.destination_ip}:{packet.destination_port}")
                        print("----------Start payload:")
                        print(Requests.requests_list[key]['payload'])
                        print("----------End Payload\n")
                        Requests.requests_list[key] = None
            pass
    
