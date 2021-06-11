#!/usr/bin/python3

import argparse
import os
import sys
from scapy.utils import RawPcapReader
from scapy.all import *


def process_pcap(file_name):
    print('Opening {}...'.format(file_name))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PCAP reader')
    parser.add_argument('--pcap', metavar='<pcap file name>',
                        help='pcap file to parse', required=True)
    args = parser.parse_args()
    
    file_name = args.pcap
    if not os.path.isfile(file_name):
        print('"{}" does not exist'.format(file_name), file=sys.stderr)
        sys.exit(-1)

    count = 0
    for (pkt_data) in RawPcapReader(file_name):
        count += 1

    print('{} contains {} packets'.format(file_name, count))


    pcap = rdpcap(file_name)
    
    ips = set((p[IP].src, p[IP].dst) for p in PcapReader(file_name) if IP in p)
    
    print(ips)
    
    process_pcap(file_name)
    sys.exit(0)
