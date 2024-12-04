from packet import Ethernet_Frame as Ethernet_Frame

class Reconstruct:
    requests_list={}
    def addPacket(packet:Ethernet_Frame):
        if packet.is_tcp_packet:
            key=f"{packet.source_ip}:{packet.source_port}->{packet.destination_ip}:{packet.destination_port}"
            if Reconstruct.requests_list.get(key) == None:
                if "HTTP" in packet.payload.split('\n')[0]:
                    Reconstruct.requests_list[key]={'sequence_number':packet.sequence_number,'request':Request(packet.payload)}
                    
                    #if Reconstruct.requests_list[key]['payload'].endswith(("\r\n","</html>")):
                    #    print(f"[+] Packet :{key}\n")
                    #    print("------------Start payload-----------")
                    #    print(Reconstruct.requests_list[key]['payload'])
                    #    print("------------End Payload-------------\n")
                    #    Reconstruct.requests_list[key] = None

            else:
                #if Reconstruct.requests_list[key]['sequence_number']<packet.sequence_number:
                #    Reconstruct.requests_list[key]['sequence_number']=packet.sequence_number
                #    Reconstruct.requests_list[key]['payload']+=packet.payload
#
                #    if Reconstruct.requests_list[key]['payload'].endswith(("\r\n","</html>")) :
                #        print(f"[+] Packet :{key}\n")
                #        print("------------Start payload-----------")
                #        print(Reconstruct.requests_list[key]['payload'])
                #        print("------------End Payload-------------\n")
                #        Reconstruct.requests_list[key] = None
                #    pass
                pass
    
class Request:
    def __init__(self,data) -> None:
        lines=[line+'\n' for line in data.split('\n')]
        
        self.request_line=lines[0]
        
        self.header_fields={}

        for i,line in enumerate(lines[1:],1):
            if line=="\r\n":
                empty_line=i
                break
            header_key=line.split(':')[0]
            header_value=line.split(':')[1].removeprefix(' ').removesuffix('\n')
            self.header_fields[header_key]=header_value
        
        self.content=None
        if self.header_fields.get('Content-Length')!=None:
            self.content="".join(lines[empty_line:])

    