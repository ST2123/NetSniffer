from struct import *
import socket

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

    total_len, identifier, flagsndoffset, ttl, protocol, source_address, destination_address = unpack('! 2x H H H B B 2x 4s 4s',data[:20])
    source_address = getIpfromHex(source_address) 
    destination_address = getIpfromHex(destination_address) 

    flags = flagsndoffset >> 13
    reserved_bit = (flags & 4) >> 2
    dont_fragment = (flags & 2) >> 1
    more_fragments = flags & 1

    flag_offset = flagsndoffset & 8191

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
        "flag_offset": flag_offset,
        "ttl": ttl,
        "protocol": protocol,
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
        "flag_urg": flag_urg,
        "flag_ack": flag_ack,
        "flag_psh": flag_psh,
        "flag_rst": flag_rst,
        "flag_syn": flag_syn,
        "flag_fin": flag_fin,
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

Protocols = {
    1: ("ICMP", Protocol_ICMP_Decode),
    6: ("TCP", Protocol_TCP_Decode),
    17: ("UDP", Protocol_UDP_Decode),
    90: "Sprite-RPC",
    }