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