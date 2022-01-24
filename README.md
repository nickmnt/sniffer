# <span style="color:#007FFF">Packet Sniffer project</span>
This project is the second project for my university's networking course.
## <span style="color:#007FFF">Introduction</span>
The goal is to sniff packets in the network and show packet information such as source, destination, TTL, packet length, ...

 - The tool works with the following protocols: HTTP, ICMP, UDP, TCP,
   Ethernet, ARP and SSH.
 - Like wireshark, for every packet that passes through the network, the
   tool shows: Source, Destination, Protocol, Packet Length, TTL
 - For each of the above protocols, the tool analyzes the packet headers
   and show the specified details


<br />
 <p align="center">
<img style="width: 10rem;height:10rem; margin-right: 2rem" src="https://upload.wikimedia.org/wikipedia/commons/thumb/c/c3/Python-logo-notext.svg/300px-Python-logo-notext.svg.png" />
</p>
<br />
<p align="center" style="font-size: 1.6rem; font-weight: 600">
Made with python 3
</p>
 <p align="center">
  <img style="width: 10rem;height:10rem" src="https://www.pngplay.com/wp-content/uploads/13/Ubuntu-Transparent-Images.png"/>
</p>
<br />
<p align="center" style="font-size: 1.6rem; font-weight: 600">
Run on Ubuntu
</p>

## <span style="color:#007FFF">Documentation</span>
In this section various parts of the code is inspected.

### Initial Logic

``` python
    import socket
    
    import struct
    
    import binascii
    
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
```

Packets are received and various parts of the ethernet header is extracted, if ethernet type field is not ARP or IP the packet will not be processed by this tool.

### Print Ethernet header fields
``` python
    print('== Ethernet Header: ==')
    
    print("Destination MAC: ")
    
    print(binascii.hexlify(eth_header[0]))
    
    print("Source MAC: ")
    
    print(binascii.hexlify(eth_header[1]))
    
    print('Type: ')
    
    print(eth_type)
```
The fields we extracted from the ethernet header in the last section will be printed.
### ARP Header
``` python
    if eth_type == '0x0806':
    
	    arp_raw = packet[0][14:42]
    
	    arp_header = struct.unpack("2s2s1s1s2s6s4s6s4s", arp_raw)
    
	    print('== Arp Header: ==')
    
	    print("Hardware type: ", binascii.hexlify(arp_header[0]))
    
	    print("Protocol type: ", binascii.hexlify(arp_header[1]))
    
	    print("Hardware size: ", binascii.hexlify(arp_header[2]))
    
	    print("Protocol size: ", binascii.hexlify(arp_header[3]))
    
	    print("Opcode: ", binascii.hexlify(arp_header[4]))
    
	    print("Source MAC: ", binascii.hexlify(arp_header[5]))
    
	    print("Source IP: ", socket.inet_ntoa(arp_header[6]))
    
	    print("Dest MAC: ", binascii.hexlify(arp_header[7]))
    
	    print("Dest IP: ", socket.inet_ntoa(arp_header[8]))
```
If ARP protocol is used (again, checked using ethernet_type in the Ethernet header) extract the fields and print them to console.

## IP Protocol
``` python
    elif eth_type == '0x800':
    
	    print('== IP Header: ==')
    
	    ip_raw = packet[0][14:34]
    
	    ip_header = struct.unpack("!B1s2s2sH1sB2s4s4s", ip_raw)
    
	    version = ip_header[0] >> 4
    
	    ihl = (ip_header[0] & 15) * 4
    
	    protocol = ip_header[6]
```
If IP is being used then extract the fields from the IP header.

#### IP Flags
``` python
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
```
This code extracts the IP flag values.

#### Printing the IP header fields
``` python
    print("Version: ", version)
    
    print("IHL: ", ihl)
    
    print("Service Type: ", binascii.hexlify(ip_header[1]))
    
    print("Packet Length: ", binascii.hexlify(ip_header[2]))
    
    print("Identification: ", binascii.hexlify(ip_header[3]))
    
    print("Zero flag: ", zeroFlag)
    
    print("DF flag: ", dfFlag)
    
    print("MF flag: ", mfFlag)
    
    print("Fragment Offset: ", hex(ip_header[4] & 8191))
    
    print("TTL: ", binascii.hexlify(ip_header[5]))
    
    print("Protocol: ", protocol)
    
    print("Header Checksum: ", binascii.hexlify(ip_header[7]))
    
    print("Source IP: ", socket.inet_ntoa(ip_header[8]))
    
    print("Destination IP: ", socket.inet_ntoa(ip_header[9]))
    
    after_ip_raw = packet[0][14+ihl:]
```
The fields are printed and the raw data that comes after the IP header is saved to a variable to be used later on

### ICMP
Based on the IP Header fields, more specifically the protocol field we detect if ICMP is being used.
``` python
if protocol == 1:
    
	print('== ICMP: ==')
    
	icmp_raw = after_ip_raw[:4]
    
	icmp_type, code, checksum = struct.unpack('!BBH', icmp_raw)
    
	print("type: ", icmp_type)
    
	print("code: ", code)
    
	print("checksum: ", checksum)
```
We extract the fields and print them to the console.

### TCP 
Based on the IP Header fields, more specifically the protocol field we detect if TCP is being used.
``` python
if protocol == 6:
    
	print('== TCP: ==')
	    
	src_port, dest_port, sequence, acknowledgment, offset_with_flags, window_size, checksum, urg = struct.unpack(
	    
	'!HHLLHH2sH', after_ip_raw[:20])
	    
	tcp_header_len = (offset_with_flags >> 12) * 4
```
The TCP header fields are extracted.

#### Flags
``` python
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
```
Extracting the TCP header flags and the reserved field in the TCP header.

#### Printing the tcp header fields
``` python
print("source port: ", src_port)
    
print("dest port: ", dest_port)
    
print("sequence: ", sequence)
    
print("ack: ", acknowledgment)
    
print("header length: ", tcp_header_len)
    
print("reserved: ", reserved)
    
print("FIN flag: ", finFlag)
    
print("SYN flag: ", synFlag)
    
print("RST flag: ", rstFlag)
    
print("PSH flag: ", pshFlag)
    
print("ACK flag: ", ackFlag)
    
print("URG flag: ", urgFlag)
    
print("window size: ", window_size)
    
print("checksum: ", binascii.hexlify(checksum))
    
print("urg: ", urg)
    
after_tcp_raw = after_ip_raw[tcp_header_len:]
```
The fields are printed to console and the raw data that comes after the TCP section is prepared for later use.

### HTTP AND SSL
``` python
print('Payload:')
    
ascii_data = after_tcp_raw[:-4].decode('latin1')
    
print(ascii_data)
```
The bytes in the application layer section (the trailer is removed) is converted to text (not necessarily ascii, ascii was used as the variable name to meant text data) and printed to the console.
There is no accurate way to detect if this data is HTTP.
One could for example search for 'HTML' in the text but that would not be totally accurate.
SSL is an encrypted version of HTTP. (AKA Https)
### UDP
``` python
if protocol == 17:
    
	print('== UDP: ==')
	    
	udp_src_port, udp_dest_port, udp_len, udp_checksum = struct.unpack(
	    
	'!HHH2s', after_ip_raw[:8])
	    
	print("source port: ", udp_src_port)
	    
	print("dest port: ", udp_dest_port)
	    
	print("length: ", udp_len)
	    
	print("checksum: ", binascii.hexlify(udp_checksum))
	    
	after_udp_raw = after_ip_raw[udp_len:]
```
If the protocol is UDP, the UDP header fields are extracted and printed to console.
The raw data after the UDP section is saved to a variable but not used. 
Further than this is out of scope of this project, maybe in another project this variable could be used.. :)

### Final Code
``` python
except KeyboardInterrupt:
    
	raise SystemExit("Exiting...")
```
This code would be executed when *Ctrl + C* is used to end the tool.
