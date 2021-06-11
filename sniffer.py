#!/usr/bin/python3

from argparse import ArgumentParser
import argparse

from ifaddr import get_adapters
from scapy.all import *
from threading import Thread, Event
from time import sleep
from socket import getservbyport


class Logger():
    def __init__(self, out=False, verbose=True):
        self.out=out
        self.verbose=verbose
    def log(self, pkt):
        if self.out:
            wrpcap(self.out, pkt, append=True)
        if self.verbose:
            ip_layer = pkt.getlayer(IP)
            if ip_layer.haslayer(TCP) or ip_layer.haslayer(UDP):
                ip_layer_3_proto = 'tcp' if ip_layer.haslayer(TCP) else 'udp'
                try:
                    print("[!] New {} Packet of normal Application request {}: {}:{} -> {}:{}".format( ip_layer_3_proto.upper(), getservbyport(ip_layer.dport, ip_layer_3_proto), ip_layer.src, ip_layer.sport, ip_layer.dst, ip_layer.dport))
                except:
                    try:
                        print("[!] New {} Packet of normal Application response {}: {}:{} -> {}:{}".format( ip_layer_3_proto.upper(), getservbyport(ip_layer.sport, ip_layer_3_proto), ip_layer.src, ip_layer.sport, ip_layer.dst, ip_layer.dport))
                    except:
                        print("[!] New {} Packet {}:{} -> {}:{}".format( ip_layer_3_proto.upper(), ip_layer.src, ip_layer.sport, ip_layer.dst, ip_layer.dport))
            else:
                print("[!] New Packet {} -> {}".format(ip_layer.src, ip_layer.dst))
    

class Sniffer(Thread):
    def  __init__(self, logger, interface="eth0"):
        super().__init__()

        self.logger=logger

        self.daemon = True

        self.socket = None
        self.interface = interface
        self.stop_sniffer = Event()
    
    def __del__(self):
        print("[*] Del sniffing class {} ...".format(self.interface))

    def run(self):
        print("[*] Start sniffing {} ...".format(self.interface))
        self.socket = conf.L2listen(
            type=ETH_P_ALL,
            iface=self.interface,
            filter="ip"
        )

        sniff(
            opened_socket=self.socket,
            prn=self.logger.log,
            stop_filter=self.should_stop_sniffer
        )
    
    def stop(self):
        print("[*] Stop sniffing {} ...".format(self.interface))
        self.stop_sniffer.set()
        if self.isAlive():
            self.socket.close()

    def should_stop_sniffer(self, packet):
        return self.stop_sniffer.isSet()

parser = ArgumentParser(description='Sniffer tool')
parser.add_argument('--out','-o', metavar='out', type=str, help='pckap out file')
parser.add_argument('--interface','-i', metavar='interface', default="*", type=str, help='interface use to sniff possible value: * all eth0;eth1 eth0')

args = parser.parse_args()

interfaces_name=[]

interfaces_wanted=args.interface.split(";")

if "*" in interfaces_wanted or "any" in interfaces_wanted or "all" in interfaces_wanted:
    if len(interfaces_wanted)>1:
        print("any error")
    interfaces_name=[ ip.name for ip in get_adapters() ]
else:
    for interface in get_adapters():
        if interface.name in interfaces_wanted or any([ ip.ip in interfaces_wanted for ip in interface.ips ]):
            interfaces_name.append(interface.name)
    if len(interfaces_wanted) != len(interfaces_name):
        print("error one wanted interface is not valid")
        

sniffers=[]

logger=Logger(args.out)

for interface in interfaces_name:
    sniffer=Sniffer(logger, interface)
    sniffer.start()
    sniffers.append(sniffer)

try:
    while True:
        sleep(100)
except KeyboardInterrupt:
    for sniffer in sniffers:
        sniffer.stop()

