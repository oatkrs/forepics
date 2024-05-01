import socket
import struct
import signal
import sys
import time
import os
import argparse
import csv

#interfaceip = '192.168.1.8'
interfaceip = str(input('Enter the IP to your interface: '))
os.system('cls' if os.name == 'nt' else 'clear')
print("Initializing interface")
#animation = ["10%", "20%", "30%", "40%", "50%", "60%", "70%", "80%", "90%", "100%"]
animation = ["[■□□□□□□□□□]","[■■□□□□□□□□]", "[■■■□□□□□□□]", "[■■■■□□□□□□]", "[■■■■■□□□□□]", "[■■■■■■□□□□]", "[■■■■■■■□□□]", "[■■■■■■■■□□]", "[■■■■■■■■■□]", "[■■■■■■■■■■]"]

for i in range(len(animation)):
    time.sleep(0.2)
    sys.stdout.write("\r" + animation[i % len(animation)])
    sys.stdout.flush()

print("\n")
def ethernet_frame(data):
    dest_mac, src_mac, eth_proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(eth_proto), data[14:]

def ipv4_packet(data):
    if len(data) < 20:
        print("Error: IPv4 packet data is too short")
        return None, None, None, None, None, None, None

    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4

    if len(data) < header_length:
        print("Error: IPv4 packet header length exceeds data length")
        return None, None, None, None, None, None, None

    if len(data) < header_length + 8:
        print("Error: Not enough data for TTL, Protocol, Source IP, and Destination IP")
        return None, None, None, None, None, None, None

    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
    return '.'.join(map(str, addr))

def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

def get_protocol(proto):
    protocol_map = {
        0: 'HOPOPT',1: 'ICMP',2:'IGMP',3:'GGP',4:'IPv4',5:'ST',6:'TCP',7:'CBT',8:'EGP',9:'IGP',10:'BBN-RCC-MON',11:'NVP-II',12:'PUP',13:'ARGUS (deprecated)',14:'EMCON',15:'XNET',16:'CHAOS',17:'UDP',18:'MUX',19:'DCN-MEAS',20:'HMP',21:'PRM',22:'XNS-IDP',23:'TRUNK-1',24:'TRUNK-2',25:'LEAF-1',26:'LEAF-2',27:'RDP',28:'IRTP',29:'ISO-TP4',30:'NETBLT',31:'MFE-NSP',32:'MERIT-INP',33:'DCCP',34:'3PC',35:'IDPR',36:'XTP',37:'DDP',38:'IDPR-CMTP',39:'TP++',40:'IL',41:'IPv6',42:'SDRP',43:'IPv6-Route',44:'IPv6-Frag',45:'IDRP',46:'RSVP',47:'GRE',48:'DSR',49:'BNA',50:'ESP',51:'AH',52:'I-NLSP',53:'SWIPE (deprecated)',54:'NARP',55:'Min-IPv4',56:'TLSP',57:'SKIP',58:'IPv6-ICMP',59:'IPv6-NoNxt',60:'IPv6-Opts',61:'any host internal protocol',62:'CFTP',63:'any local network',64:'SAT-EXPAK',65:'KRYPTOLAN',66:'RVD',67:'IPPC',68:'any distributed file system',69:'SAT-MON',70:'VISA',71:'IPCV',72:'CPNX',73:'CPHB',74:'WSN',75:'PVP',76:'BR-SAT-MON',77:'SUN-ND',78:'WB-MON',79:'WB-EXPAK',80:'ISO-IP',81:'VMTP',82:'SECURE-VMTP',83:'VINES',84:'IPTM',85:'NSFNET-IGP',86:'DGP',87:'TCF',88:'EIGRP',89:'OSPFIGP',90:'Sprite-RPC',91:'LARP',92:'MTP',93:'AX.25',94:'IPIP',95:'MICP (deprecated)',96:'SCC-SP',97:'ETHERIP',98:'ENCAP',99:'any private encryption scheme',100:'GMTP',101:'IFMP',102:'PNNI',103:'PIM',104:'ARIS',105:'SCPS',106:'QNX',107:'A/N',108:'IPComp',109:'SNP',110:'Compaq-Peer',111:'IPX-in-IP',112:'VRRP',113:'PGM',114:'any 0-hop protocol',115:'L2TP',116:'DDX',117:'IATP',118:'STP',119:'SRP',120:'UTI',121:'SMP',122:'SM (deprecated)',123:'PTP',124:'ISIS over IPv4',125:'FIRE',126:'CRTP',127:'CRUDP',128:'SSCOPMCE',129:'IPLT',130:'SPS',131:'PIPE',132:'SCTP',133:'FC',134:'RSVP-E2E-IGNORE',135:'Mobility Header',136:'UDPLite',137:'MPLS-in-IP',138:'manet',139:'HIP',140:'Shim6',141:'WESP',142:'ROHC',143:'Ethernet',144:'AGGFRAG',145:'NSH',253:'Used for experimentation and testing',254:'Used for experimentation and testing',255:'Reserved',
    }
    return protocol_map.get(proto, str(proto))

def get_source_port(data):
    try:
        if True:
            return struct.unpack('! H', data[:2])[0]
    except (IndexError, AttributeError, struct.error):
        return None

def get_destination_port(data):
    try:
        if True:
            return struct.unpack('! H', data[2:4])[0]
    except (IndexError, AttributeError, struct.error):
        return None

def write_to_file(output_file, packet_data):
    with open(output_file, 'a') as f:
        f.write(packet_data)

def write_to_csv(output_file, packet_data):
    with open(output_file, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(packet_data)

logo = r'''
 ______  _____   _____  ______       _______ __   _ _____ _______ _______ _______  ______
|  ____ |     | |     | |     \      |______ | \  |   |   |______ |______ |______ |_____/
|_____| |_____| |_____| |_____/      ______| |  \_| __|__ |       |       |______ |    \_


       .-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-.
       :                                                                       :
       .     PRESS CTRL+C TO STOP THE SCRIPT AFTER IT STARTS SNIFFING          .
       .                                                                       .
       .    run again with 'python goodsniffer.py -o file' to save sniffs      .
       :                                                                       :
       `-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=tdwg-'
                                                                                 '''


def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    print('WELCOME TO THE', end='')
    print(logo)
    parser = argparse.ArgumentParser(description='The hardest sniffer ever')
    parser.add_argument('-o', '--output', type=str, help='output file')
    args = parser.parse_args()
    capture_eth_data = input('Do you want to capture Hexed Ethernet Data (Hexdump) (y for yes, anything else to ignore)? ').lower() == 'y'
    capture_raweth_data = input('Do you want to capture Raw Ethernet Data (y for yes, anything else to ignore)? ').lower() == 'y'
    print('STARTING NOW (if this is the only thing visible, then the packets have\'nt exactly started flowing yet)')
    conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    conn.bind((interfaceip, 0))
    conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    serial_number = 0

    t1 = time.time()#timestamp1

    try:
        while True:
            raw_data, addr = conn.recvfrom(65536)
            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
            version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())

            serial_number += 1

            packet_data = f'===================================\n\nSerial Number: {serial_number}\nTimestamp: {timestamp}\nProtocol number: {(proto)}\nProtocol name: {get_protocol(proto)}\nPacket Length: {len(raw_data)} bytes\nDestination MAC: {dest_mac}\nSource MAC: {src_mac}\nDestination Host: {target}\nSource Host: {src}\nDestination Port: {get_destination_port(data)}\nSource Port: {get_source_port(data)}\n'

            if capture_eth_data:
                packet_data += f'Hex Ethernet Data: {data.hex()}\n'
            if capture_raweth_data:
                packet_data += f'Raw Ethernet Data: {data}\n'

            print(packet_data)

            if args.output:
                write_to_file(args.output + '.txt', packet_data)
                write_to_csv(args.output + '.csv', [serial_number, timestamp, proto, get_protocol(proto), len(raw_data), dest_mac, src_mac, target, src, get_destination_port(data), get_source_port(data), data.hex() if capture_eth_data else None, data if capture_raweth_data else None])

    except KeyboardInterrupt:
        t2=time.time()#timestamp2
        t=t2-t1
        print('\nSniffing stopped successfully\n')
        print(f'Successfully sniffed  {serial_number} packets in {t} seconds')
if __name__ == '__main__':
    main()