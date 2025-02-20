# Keep Your Eyes Peeled (HTTP Sniffer)

This project is a simple HTTP Sniffer written in python3.

### Example usage:
```bash
 sudo python3 main.py --interface eth0
```

### Broken into 3 parts:
- main.py : running the program
- requests.py : rebuilding the HTTP request
- packet.py : parsing the packets (Ethernet Frame -> IP Packet -> TCP Packet -> HTTP Packet)

### Arguments:
```bash
-h, --help            show this help message and exit
--interface INTERFACE
                      Network interface to sniff on (e.g., wlan0, eth0)
--source_ip SOURCE_IP
                      Source IP address to filter packets
--destination_ip DESTINATION_IP
                      Destination IP address to filter packets
--source_port SOURCE_PORT
                      Source port to filter packets
--destination_port DESTINATION_PORT
                      Destination port to filter packets
--type_request TYPE_REQUEST
                      Type of request (e.g., GET, POST)
--headers [HEADERS ...]
                      List of header keys and values (key1:value1 key2:value2)
--content CONTENT     Content to filter in the packet
--record              Flag to start recording traffic
--verbose             Flag to display payloads
```