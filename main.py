x= \
"""
    author:     ST2123
    githum:     https://github.com/ST2123
    licence:    ??
"""
from netsnifr import decode
import socket
import pprint

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

packet_list = []

def sniff():
    while True:   
        data = s.recvfrom(65565)
        packet = decode.Decode_packet(data[0])
        print()
        decode.print_packet(packet,show_data=False)
        #pprint.pprint(packet)
        #packet_list.append(packet)

def send_packet():
    print("no sending yet! :D")

# ====================================================
print("==========================")
print("=== NetSnifr by ST2123 ===")
print("==========================")

while True:
    print()
    print("Options:")
    print("0) packet sniff")
    print("1) send packet")
    print("enter option number -> ", end="")

    try:
        opt = int(input())
    except Exception:
        pass
    
    if opt == 0:
        sniff()
    elif opt == 1:
        send_packet()