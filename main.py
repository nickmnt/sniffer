import socket
import struct
import binascii

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

try: 
  print("Packet sniffer project, Student # 9822762211")
  while True:
    packet = s.recvfrom(65565)

    ethernet_header = packet[0][0:14]
    eth_header = struct.unpack("!6s6s2s", ethernet_header)
    
    print("Destination MAC:")
    print(binascii.hexlify(eth_header[0]))
    print(" Source MAC:")
    print(binascii.hexlify(eth_header[1]))
    print(" Type:" )
    print(binascii.hexlify(eth_header[2]))

    ipheader = packet[0][14:34]
    ip_header = struct.unpack("!12s4s4s", ipheader)
    print("Source IP:" + socket.inet_ntoa(ip_header[1]) + " Destination IP:" + socket.inet_ntoa(ip_header[2]))
except KeyboardInterrupt:
  raise SystemExit("Exiting...")