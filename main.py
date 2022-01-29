import socket
import struct
import binascii

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

try: 
  print("Packet sniffer project, Student # 9822762211")
  while True:
    packet = s.recvfrom(65565)

    ethernet_raw = packet[0][0:14]
    eth_header = struct.unpack("!6s6sH", ethernet_raw)
    
    eth_type = hex(eth_header[2])

    if eth_type != '0x800' and eth_type != '0x0806':
      continue

    print(bcolors.OKGREEN + '== Ethernet Header: ==' + bcolors.ENDC)
    print("Destination MAC:   ")
    print(binascii.hexlify(eth_header[0]))
    print("Source MAC:        ")
    print(binascii.hexlify(eth_header[1]))
    print('Type:              ')
    print(eth_type)

    if eth_type == '0x0806':
      arp_raw = packet[0][14:42]
      arp_header = struct.unpack("2s2s1s1s2s6s4s6s4s", arp_raw)
      print(bcolors.OKGREEN + '== Arp Header: =='  + bcolors.ENDC)
      print("Hardware type:   ", binascii.hexlify(arp_header[0]))
      print("Protocol type:   ", binascii.hexlify(arp_header[1]))
      print("Hardware size:   ", binascii.hexlify(arp_header[2]))
      print("Protocol size:   ", binascii.hexlify(arp_header[3]))
      print("Opcode:          ", binascii.hexlify(arp_header[4]))
      print("Source MAC:      ", binascii.hexlify(arp_header[5]))
      print("Source IP:       ", socket.inet_ntoa(arp_header[6]))
      print("Dest MAC:        ", binascii.hexlify(arp_header[7]))
      print("Dest IP:         ", socket.inet_ntoa(arp_header[8]))
    elif eth_type == '0x800':
      print(bcolors.OKGREEN + '== IP Header: ==' + bcolors.ENDC)
      ip_raw = packet[0][14:34]
      ip_header = struct.unpack("!B1s2s2sH1sB2s4s4s", ip_raw)
      version = ip_header[0] >> 4
      ihl = (ip_header[0] & 15) * 4
      protocol = ip_header[6]

      if ip_header[4] & 32768 == 32768:
        zeroFlag = 1
      else:
        zeroFlag = 0

      if ip_header[4] & 16384 == 16384:
        dfFlag = 1
      else:
        dfFlag = 0

      if ip_header[4] & 8192 == 8192:
        mfFlag = 1
      else:
        mfFlag = 0

      print("Version:         ", version)
      print("IHL:             ", ihl)
      print("Service Type:    ", binascii.hexlify(ip_header[1]))
      print("Packet Length:   ", binascii.hexlify(ip_header[2]))
      print("Identification:  ", binascii.hexlify(ip_header[3]))
      print("Zero flag:       ", zeroFlag)
      print("DF   flag:       ", dfFlag)
      print("MF   flag:       ", mfFlag)
      print("Fragment Offset: ", hex(ip_header[4] & 8191))
      print("TTL:             ", binascii.hexlify(ip_header[5]))
      print("Protocol:        ", protocol)
      print("Header Checksum: ", binascii.hexlify(ip_header[7]))
      print("Source IP:       ", socket.inet_ntoa(ip_header[8]))
      print("Destination IP:  ", socket.inet_ntoa(ip_header[9]))

      after_ip_raw = packet[0][14+ihl:]
      
      if protocol == 1:
        print(bcolors.OKGREEN + '== ICMP: =='  + bcolors.ENDC)
        icmp_raw = after_ip_raw[:4]
        icmp_type, code, checksum = struct.unpack('!BBH', icmp_raw)
        print("type:          ", icmp_type)
        print("code:          ", code)
        print("checksum:      ", checksum)
      if protocol == 6:
        print(bcolors.OKGREEN + '== TCP: =='  + bcolors.ENDC)
        src_port, dest_port, sequence, acknowledgment, offset_with_flags, window_size, checksum, urg = struct.unpack(
            '!HHLLHH2sH', after_ip_raw[:20])
        tcp_header_len = (offset_with_flags >> 12) * 4

        if offset_with_flags & 1 == 1:
          finFlag = 1
        else:
          finFlag = 0

        if offset_with_flags & 2 == 2:
          synFlag = 1
        else:
          synFlag = 0

        if offset_with_flags & 4 == 4:
          rstFlag = 1
        else:
          rstFlag = 0

        if offset_with_flags & 8 == 8:
          pshFlag = 1
        else:
          pshFlag = 0

        if offset_with_flags & 16 == 16:
          ackFlag = 1
        else:
          ackFlag = 0

        if offset_with_flags & 32 == 32:
          urgFlag = 1
        else:
          urgFlag = 0

        reserved = hex(offset_with_flags & 4032)

        print("source port:   ", src_port)
        print("dest port:     ", dest_port)
        print("sequence:      ", sequence)
        print("ack:           ", acknowledgment)
        print("header length: ", tcp_header_len)
        print("reserved:      ", reserved)
        print("FIN flag:      ", finFlag)
        print("SYN flag:      ", synFlag)
        print("RST flag:      ", rstFlag)
        print("PSH flag:      ", pshFlag)
        print("ACK flag:      ", ackFlag)
        print("URG flag:      ", urgFlag)
        print("window size:   ", window_size)
        print("checksum:      ", binascii.hexlify(checksum))
        print("urg:           ", urg)

        after_tcp_raw = after_ip_raw[tcp_header_len:]

        if src_port == 443 or dest_port == 443:
          print(bcolors.OKGREEN + '== SSL: ==' + bcolors.ENDC)
        if src_port == 80 or dest_port == 80:
          print(bcolors.OKGREEN + '== HTTP: ==' + bcolors.ENDC)
        
        print('Payload:')
        text_data = after_tcp_raw[:-4].decode('latin1')
        print(text_data)
      if protocol == 17:
        print(bcolors.OKGREEN + '== UDP: =='  + bcolors.ENDC)
        udp_src_port, udp_dest_port, udp_len, udp_checksum = struct.unpack(
            '!HHH2s', after_ip_raw[:8])
        print("source port:   ", udp_src_port)
        print("dest port:     ", udp_dest_port)
        print("length:        ", udp_len)
        print("checksum:      ", binascii.hexlify(udp_checksum))

        after_udp_raw = after_ip_raw[udp_len:]

      print('**************************')
except KeyboardInterrupt:
  raise SystemExit("Exiting...")
