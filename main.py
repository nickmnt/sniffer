import socket

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

try: 
  print("Packet sniffer project, Student # 9822762211")
  while True:
    print(s.recvfrom(65565))
except KeyboardInterrupt:
  raise SystemExit("Exiting...")