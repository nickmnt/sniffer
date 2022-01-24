import socket
import struct
import binascii

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

try: 
  print("Packet sniffer project, Student # 9822762211")
  while True:
    packet = s.recvfrom(65565)

    ethernet_raw = packet[0][0:14]
    eth_header = struct.unpack("!6s6s2s", ethernet_raw)
    
    eth_type = eth_header[2]

    # if eth_type != '\x08\x06':
      # continue

    print('== Ethernet Header: ==')
    print("Destination MAC:   ")
    print(binascii.hexlify(eth_header[0]))
    print("Source MAC:        ")
    print(binascii.hexlify(eth_header[1]))
    print("Type:              " )
    print(binascii.hexlify(eth_type))
    print()

    if eth_type == '\x08\x06':
      arp_raw = packet[0][14:42]
      arp_header = struct.unpack("2s2s1s1s2s6s4s6s4s", arp_raw)
      print('== Arp Header: ==')
      print("Hardware type:   ", binascii.hexlify(arp_header[0]))
      print("Protocol type:   ", binascii.hexlify(arp_header[1]))
      print("Hardware size:   ", binascii.hexlify(arp_header[2]))
      print("Protocol size:   ", binascii.hexlify(arp_header[3]))
      print("Opcode:          ", binascii.hexlify(arp_header[4]))
      print("Source MAC:      ", binascii.hexlify(arp_header[5]))
      print("Source IP:       ", socket.inet_ntoa(arp_header[6]))
      print("Dest MAC:        ", binascii.hexlify(arp_header[7]))
      print("Dest IP:         ", socket.inet_ntoa(arp_header[8]))
    else:
      print('== IP Header: ==')
      ipheader = packet[0][14:34]
      ip_header = struct.unpack("!12s4s4s", ipheader)
      print("Source IP:       ", socket.inet_ntoa(ip_header[1]))
      print("Destination IP:  ", socket.inet_ntoa(ip_header[2]))
except KeyboardInterrupt:
  raise SystemExit("Exiting...")