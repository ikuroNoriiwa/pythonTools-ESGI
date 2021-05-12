#!/usr/bin/python3

from argparse import ArgumentParser
from sys import exit, stderr

from ipaddress import ip_address, ip_network

from ping import range_ip

"""
Usage
Domain enum:
    python3 main.py dns --domain domain.totest

Domain reverse resolve:
    python3 main.py dns --net 192.168.1.0/24

Ping:
    python3 main.py ping --net 192.168.1.0-192.168.1.198,10.1.0.0

Scan:
    python3 main.py scan --net 10.1.0.0
"""



parser = ArgumentParser(description='Port scaning')
parser.add_argument('--thread','--threads','-t', metavar='thread', default=10, type=int, help='Change default threads use')
parser.add_argument('--out','-o', metavar='out', default=10, type=int, help='out file')

subparsers = parser.add_subparsers(help='need one argument', dest='action')
subparsers.required = True


parser_ping = subparsers.add_parser('ping', help='ping help')
parser_ping.add_argument('--net', '--nets', '-n', metavar='net', type=str, required=True, help='net list xx-xx,xx/xx|xx')


parser_scan = subparsers.add_parser('scan', help='scan help')
parser_scan.add_argument('--net', '--nets', '-n', metavar='net', type=str, required=True, help='net list xx-xx,xx/xx|xx')
parser_scan.add_argument('--port', '--port-range', '--port-ranges','--ports','-p', metavar='port', default="1-65555", type=str, help='port list xx-xx,xx|xx')

parser_dns = subparsers.add_parser('dns', help='dns help')
parser_dns.add_argument('--port','--ports','-p', metavar='port', default=53, type=int, help='non-standart port xx')
parser_dns.add_argument('--dns', metavar='dns', type=str, help='specific dns server')

choice_parser_dns = parser_dns.add_mutually_exclusive_group(required=True)
choice_parser_dns.add_argument('--net', '--nets', '-n', metavar='net', type=str, help='net list xx-xx,xx/xx|xx')
choice_parser_dns.add_argument('--domain', '--domains','-d', metavar='domain', type=str, help='domain to brute force XXXXXXXXXXX,XXXXXXXXXXXX,XXXXXXXXXXXX|XXXXXXXXXXXXXXX')
domain_parser_dns = parser_dns.add_mutually_exclusive_group()
domain_parser_dns.add_argument('--file', '-f', metavar='file', type=str, help='need an input file')
domain_parser_dns.add_argument('--brute', '--brute-force', '-b', '--gen', '-g', metavar='brute', type=str, help='brute force hostname')

def check_net_input(netstr):
    nets=[]
    errors=[]
    for net in netstr.split(','):
        if net == '':
            pass
        if '-' in net:
            net=net.split('-')
            net_ip=[]
            for ip in net:
                try:
                    ip_obj = ip_address(ip)
                    net_ip.append(ip_obj)
                except ValueError:
                    errors.append("Invalide ip:{} format in range:{}".format(ip, net))
            if len(net_ip) ==2 and net_ip[0]>net_ip[1]:
                errors.append("Invalide range:{} ip0 > ip1 ".format( net))            
            else :
                nets.append(net_ip)
        elif '/' in net:
            try:
                net_hosts = list(ip_network(net).hosts())
                nets.append([net_hosts[0],net_hosts[-1]])
            except ValueError:
                errors.append("Invalide network:{}".format(net))
        else:
            try:
                ip_obj = ip_address(net)
                nets.append([ip_obj,ip_obj])
            except ValueError:
                errors.append("Invalide ip:{}".format(net))
    return (nets, errors)


def run_on_nets(func, nets):
    out = []
    for net in nets:
        out += func(net[0], net[1], args.thread)
    return out


args = parser.parse_args()      

## string array out info
out=[]
if args.action == 'dns' and 'domain' in args:
    if not args.brute and not args.file:
        parser.print_help()
        exit(1)
else:
    
    nets, errors = check_net_input(args.net)
    
    if len(errors)!=0:
        print("\033[41mWe found the following errors:\033[0m", file=stderr)
        for err in errors:
            print("\033[91m{}\033[0m".format(err), file=stderr)
        exit(1)

    if args.action == 'dns':
        print("TODO dns reverse")
    elif args.action == 'scan':
        print("TODO scan")    
    elif args.action == 'ping':
        out = run_on_nets(range_ip, nets)

## TODO export out to a file if option