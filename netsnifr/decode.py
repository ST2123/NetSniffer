from struct import *
import socket
import binascii

def Decode_packet(data):
    decoded_data = {}

    dtlist = Decode_Network_Layer(data)
    decoded_data["network"] = dtlist[0]
    data = dtlist[1]

    dtlist = Decode_Internet_Layer(data)
    decoded_data["internet"] = dtlist[0]
    data = dtlist[1]

    dtlist = Decode_Application_layer(data,decoded_data["internet"]["protocol"])
    decoded_data["application"] = dtlist[0]
    data = dtlist[1]

    if len(data) > 0:
        decoded_data["data"] = data

    return decoded_data


def Decode_Network_Layer(data):
    dest, src, proto_type = unpack('! 6s 6s H', data[:14])        

    dest = map('{:02x}'.format, dest)
    dest = ":".join(dest)

    src = map('{:02x}'.format, src)
    src = ":".join(src)

    proto_type = socket.htons(proto_type)

    return {
        "dest": dest,
        "src": src,
        "type": proto_type
    }, data[14:]


def Decode_Internet_Layer(data):
    version = data[0] >> 4
    IHL = data[0] & 15
    Type_of_service = data[1]

    total_len, identifier, flagsndoffset, ttl, protocol, checksum, source_address, destination_address = unpack('! 2x H H H B B H 4s 4s',data[:20])
    source_address = getIpfromHex(source_address) 
    destination_address = getIpfromHex(destination_address) 

    flags = flagsndoffset >> 13
    reserved_bit = (flags & 4) >> 2
    dont_fragment = (flags & 2) >> 1
    more_fragments = flags & 1

    offset = flagsndoffset & 8191

    return {
        "version": version,
        "IHL": IHL,
        "TOS": Type_of_service,
        "total_len": total_len,
        "identifier": identifier,
        "flags": {
            "reserved_bit": reserved_bit,
            "dont_fragment": dont_fragment,
            "more_fragments": more_fragments,
        },
        "offset": offset,
        "ttl": ttl,
        "protocol": protocol,
        "checksum": checksum,
        "src": source_address,
        "dest": destination_address,
    },data[IHL*4:]


def Decode_Application_layer(data, protocol):
    try:
        return Protocols[protocol][1](data)
    except Exception as e:
        #print("error:",e)
        return None, data


def Protocol_ICMP_Decode(data):
    icmp_type, code, checksum = unpack('! B B H', data[:4])
    return {
        "icmp_type": icmp_type,
        "code": code,
        "checksum": checksum
        }, data[4:]


def Protocol_TCP_Decode(data):
    src_port, dest_port, sequence, acknowledgenment, offset, flags, window_size, checksum, urgent_pointer = unpack('! H H L L B B H H H', data[:20])
    offset = offset >> 4
    flag_urg = (flags & 32) >> 5
    flag_ack = (flags & 16) >> 4
    flag_psh = (flags & 8) >> 3
    flag_rst = (flags & 4) >> 2
    flag_syn = (flags & 2) >> 1
    flag_fin = flags & 1

    return {
        "src_port": src_port,
        "dest_port": dest_port,
        "sequence": sequence,
        "acknowledgenment": acknowledgenment,
        "flags":{
            "flag_urg": flag_urg,
            "flag_ack": flag_ack,
            "flag_psh": flag_psh,
            "flag_rst": flag_rst,
            "flag_syn": flag_syn,
            "flag_fin": flag_fin,
        },
        "window_size": window_size,
        "checksum": checksum,
        "urgent_pointer": urgent_pointer
    }, data[offset*4:]

def Protocol_UDP_Decode(data):
    src_port, dest_port, size = unpack('! H H 2x H', data[:8])
    return {
        "src_port": src_port,
        "dest_port": dest_port,
        "size": size
    }, data[8:]

def getIpfromHex(hexcode):
        return ".".join(map(str,hexcode))

def get_prototext_from_num(num):
    try:
        return Protocols[num][0]
    except Exception:
        return num

def get_int_flags(flags):
    flgs = []
    if flags["reserved_bit"] == 1:
        flgs.append("Reserved bit")
    if flags["dont_fragment"] == 1:
        flgs.append("Don't fragment")
    if flags["more_fragments"] == 1:
        flgs.append("More fragments")

    if len(flgs)>0:
        return ", ".join(flgs)
    else:
        return "No flag"

def get_app_flags(flags):
    flgs = []

    if flags["flag_urg"] == 1:
        flgs.append("URG")
    if flags["flag_ack"] == 1:
        flgs.append("ACK")
    if flags["flag_psh"] == 1:
        flgs.append("PSH")
    if flags["flag_rst"] == 1:
        flgs.append("RST")
    if flags["flag_syn"] == 1:
        flgs.append("SYN")
    if flags["flag_fin"] == 1:
        flgs.append("FIN")

    if len(flgs)>0:
        return ", ".join(flgs)
    else:
        return "No flag"

def __print_ICMP_packet(packet):
    app_layer = packet["application"]
    icmp_type = app_layer["icmp_type"]
    code = app_layer["code"]
    checksum = app_layer["checksum"]

    print(f"Type:{icmp_type}|Code:{code}|Checksum:{checksum}")

def __print_TCP_packet(packet):
    app_layer = packet["application"]
    port_src = app_layer["src_port"]
    port_dest = app_layer["dest_port"]
    ack = app_layer["acknowledgenment"]
    flags = get_app_flags(app_layer["flags"])
    window_size = app_layer["window_size"]
    checksum = app_layer["checksum"]
    urgent_pointer = app_layer["urgent_pointer"]
    print(f"Port:{port_src}->{port_dest}|ACK:{ack}|Flags:{flags}|Window size:{window_size}|Checksum:{checksum}|Urgent pointer:{urgent_pointer}")
    
def __print_UDP_packet(packet):
    app_layer = packet["application"]
    port_src = app_layer["src_port"]
    port_dest = app_layer["dest_port"]
    size = app_layer["size"]
    print(f"Port:{port_src}->{port_dest}|Size:{size}")

def print_packet(packet, show_data=False):
    net_layer = packet["network"]
    mac_src = net_layer["src"]
    mac_dest = net_layer["dest"]

    int_layer = packet["internet"]
    version = int_layer["version"]
    IHL = int_layer["IHL"]
    TOS = int_layer["TOS"]
    total_len = int_layer["total_len"]
    identifier = int_layer["identifier"]
    flags = get_int_flags(int_layer["flags"])
    offset = int_layer["offset"]
    ttl  = int_layer["ttl"]
    protocol = int_layer["protocol"]
    protocol_txt = get_prototext_from_num(protocol)
    checksum = int_layer["checksum"]
    ip_src = int_layer["src"]
    ip_dest = int_layer["dest"]

    print(f"{ip_src}({mac_src}) -> {ip_dest}({mac_dest})")
    print(f"Version:{version}|IHL:{IHL}|TOS:{TOS}|Total_lenght:{total_len}|Identifier:{identifier}|checksum:{checksum}")
    print(f"Protocol:{protocol}({protocol_txt})|TTL:{ttl}|Flags:{flags}|Offset:{offset}")

    try:
        Protocols[protocol][2](packet)
    except Exception as e:
        print("err:",e)
        print("cant print protocol:",protocol)

        
    if show_data and  "data" in packet:
        dt = packet["data"]
        dt = binascii.hexlify(dt, ' ')
        print(dt)

Protocols = {
    1: ("ICMP", Protocol_ICMP_Decode,__print_ICMP_packet),
    6: ("TCP", Protocol_TCP_Decode,__print_TCP_packet),
    17: ("UDP", Protocol_UDP_Decode,__print_UDP_packet),
    90: "Sprite-RPC",
    }