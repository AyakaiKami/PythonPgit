from packet import Ethernet_Frame as Ethernet_Frame

class Reconstruct:
    requests_return_list=[]
    requests_list={}
    def addPacket(packet:Ethernet_Frame):
        if packet.is_tcp_packet:
            key=f"{packet.source_ip}:{packet.source_port}->{packet.destination_ip}:{packet.destination_port}"
            if Reconstruct.requests_list.get(key) == None:
                if "HTTP" in packet.payload.split('\n')[0]:
                    Reconstruct.requests_list[key]={'sequence_number':packet.sequence_number,'request':Request(packet.payload,packet.source_ip,packet.source_port,packet.destination_ip,packet.destination_port)}
                    
                    if Reconstruct.requests_list[key]['request'].is_full():
                        #print(f"[+] Packet :{key}\n")
                        #print("------------Start request-----------")
                        #print(Reconstruct.requests_list[key]['request'])
                        #print("------------End request-------------\n")
                        Reconstruct.requests_return_list.append(Reconstruct.requests_list[key]['request'])
                        Reconstruct.requests_list[key] = None

            else:
                if Reconstruct.requests_list[key]['sequence_number']<packet.sequence_number:
                    Reconstruct.requests_list[key]['sequence_number']=packet.sequence_number
                    Reconstruct.requests_list[key]['request'].append(packet.payload)
                    if Reconstruct.requests_list[key]['request'].is_full():
                        #print(f"[+] Packet :{key}\n")
                        #print("------------Start request-----------")
                        #print(Reconstruct.requests_list[key]['request'])
                        #print("------------End request-------------\n")
                        Reconstruct.requests_return_list.append(Reconstruct.requests_list[key]['request'])
                        Reconstruct.requests_list[key] = None
    def getLastRequest():
        if Reconstruct.requests_return_list!=[]:
            return Reconstruct.requests_return_list[-1]
        return None
    def loseAll():
        Reconstruct.requests_return_list=[]
class Request:
    def __init__(self,data,source_ip,source_port,destination_ip,destination_port) -> None:
        lines=[line+'\n' for line in data.split('\n')]
        self.request_line=str(lines[0])
        self.source_ip=str(source_ip)
        self.source_port=int(source_port)
        self.destination_ip=str(destination_ip)
        self.destination_port=int(destination_port)
        self.header_fields={}

        self.is_empty_line_set=False
        self.empty_line=0

        for i,line in enumerate(lines[1:],1):
            self.empty_line=i
            if line=="\r\n":
                self.is_empty_line_set=True
                break

            header_key=line.split(':')[0]
            header_value=line.split(':')[1].removeprefix(' ').removesuffix('\n').removesuffix('\r')
            
            if header_key=='X-Content-Type-Options':
                #print(f"{header_key}: {header_value}")
                pass

            self.header_fields[header_key] = header_value

        self.content=None
        self.is_over=False
        if self.header_fields.get('Content-Length') is not None:
            self.content="".join(lines[self.empty_line+1:])
            if len(self.content)==int(self.header_fields['Content-Length']):
                self.is_over=True
        else:
            if self.is_empty_line_set:
                self.is_over=True

    def append(self,data)->None:
        lines=[line+'\n' for line in data.split('\n')]

        if not self.is_empty_line_set:
            last_empty_line=self.empty_line
            for i,line in enumerate(lines,last_empty_line+1):
                self.empty_line=i
                if line=="\r\n":
                    self.is_empty_line_set=True
                    break
                header_key=line.split(':')[0]
                header_value=line.split(':')[1].removeprefix(' ').removesuffix('\n')
                
                self.header_fields[header_key] = header_value
                

            self.content=None
            self.is_over=False
            if self.header_fields.get('Content-Length')!=None:
                self.content+="".join(lines[self.empty_line+1:])
                if len(self.content)==self.header_fields['Content-Length']:
                    self.is_over=True
            else:
                if self.is_empty_line_set:
                    self.is_over=True
        else:
            self.content+="".join(lines)
            
            if len(self.content)>=int(self.header_fields['Content-Length']):
                self.is_over=True

    def is_full(self):
        return self.is_over
    
    def __str__(self) -> str:
        buffer=f"Request from {self.source_ip}:{self.source_port} to {self.destination_ip}:{self.destination_port}\n"
        buffer+="----------Start Request----------\n"
        buffer+=self.request_line
        for key,value in self.header_fields.items():
            buffer+=f"{key}: {value}\n"
        
        buffer+="\n"
        if self.content!=None:
            buffer+=self.content
        buffer+="----------End Request-------------\n"
        return buffer