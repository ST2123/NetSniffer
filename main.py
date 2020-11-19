from sniffer import decode
import socket
import pprint

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

data_on_port={}

while True:   
    data = s.recvfrom(65565)
    pprint.pprint(decode.Decode_packet(data[0]))
