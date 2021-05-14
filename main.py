#!/usr/bin/python3

from argparse import ArgumentParser

from ipaddress import ip_address, ip_network

from resolve import resolve_file

from reverse import range_ip as reverse_range_ip

from ping import range_ip as ping_range_ip

from tools import error

"""
Usage
Domain enum:
    python3 main.py dns --domain domain.totest

Domain reverse resolve:
    python3 main.py dns --net 192.168.1.0/24
    
    ## Check https://github.com/OWASP/Amass/blob/master/examples/wordlists/ for other
    curl -L https://github.com/OWASP/Amass/raw/master/examples/wordlists/subdomains.lst -o /tmp/subdomains.lst \
        && python3 main.py dns -d test.com --file /tmp/subdomains.lst

Ping:
    python3 main.py ping --net 192.168.1.0-192.168.1.198,10.1.0.0

Scan:
    python3 main.py scan --net 10.1.0.0
"""



parser = ArgumentParser(description='Scanning tool')
parser.add_argument('--thread','--threads','-t', metavar='thread', default=10, type=int, help='Change default threads use')
parser.add_argument('--out','-o', metavar='out', default="", type=str, help='out file')

subparsers = parser.add_subparsers(help='need one argument', dest='action')
subparsers.required = True


parser_ping = subparsers.add_parser('ping', help='ping help')
parser_ping.add_argument('--net', '--nets', '-n', metavar='net', type=str, required=True, help='net list xx-xx,xx/xx|xx')


parser_scan = subparsers.add_parser('scan', help='scan help')
parser_scan.add_argument('--net', '--nets', '-n', metavar='net', type=str, required=True, help='net list xx-xx,xx/xx|xx')
parser_scan.add_argument('--port', '--port-range', '--port-ranges','--ports','-p', metavar='port', default="1-65555", type=str, help='port list xx-xx,xx|xx')

parser_dns = subparsers.add_parser('dns', help='dns (--net | --domain (--file | --brute)')
parser_dns.add_argument('--port','--ports','-p', metavar='port', default=53, type=int, help='non-standart port xx')
parser_dns.add_argument('--dns', metavar='dns', default="", type=str, help='specific dns server')

choice_parser_dns = parser_dns.add_mutually_exclusive_group(required=True)
choice_parser_dns.add_argument('--net', '--nets', '-n', metavar='net', type=str, help='net list xx-xx,xx/xx|xx')
choice_parser_dns.add_argument('--domain', '--domains','-d', metavar='domain', type=str, help='domain to brute force XXXXXXXXXXX,XXXXXXXXXXXX,XXXXXXXXXXXX|XXXXXXXXXXXXXXX')
domain_parser_dns = parser_dns.add_mutually_exclusive_group()
domain_parser_dns.add_argument('--file', '-f', metavar='file', type=str, help='need an input file')
domain_parser_dns.add_argument('--brute', '--brute-force', '-b', '--gen', '-g', action='store_true', default=False, help='brute force hostname')

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

args = parser.parse_args()      

## string array out info
out=[]

if args.action =='dns' and args.dns != "":
    errors=[]
    for ip in args.dns.split(','):
        try:
            ip_obj = ip_address(ip)
        except ValueError:
            errors.append("Invalide ip:{}".format(ip))
    error("We found the following errors during dns ip parsing:", errors)
        

if args.action == 'dns' and args.domain:
    if not args.brute and not args.file:
        parser.print_help()
        exit(1)
    if args.file:
        resolve_file(args.domain, args.file, args.dns.split(',') if args.dns!="" else [], args.port, args.thread , verbose=True, file= False if args.out == "" else args.out)
    elif args.brute:
        print("TODO brute force dns")
else:
    nets, errors = check_net_input(args.net)
    
    error("We found the following errors during net range parsing:", errors)

    if args.action == 'dns':
        for net in nets:
            out += reverse_range_ip(net[0], net[1], args.dns.split(',') if args.dns!="" else [], args.port ,args.thread)
    elif args.action == 'scan':
        print("TODO scan")    
    elif args.action == 'ping':
        for net in nets:
            out += ping_range_ip(net[0], net[1], args.thread)

## TODO export out to a file if option