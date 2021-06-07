#!/usr/bin/python3

from sys import prefix
from dns.resolver import Resolver
from dns.exception import Timeout as DnsTimeout
from dns.resolver import NoAnswer, NoNameservers
from dns.name import EmptyLabel
from concurrent.futures import as_completed, ThreadPoolExecutor, thread
from tools import error, Output
from itertools import islice
from string import ascii_lowercase, digits

def resolving(host, resolver, rs_type="A", i=0):
    try:
        return (1, list(map(str ,resolver(host, "A"))))
    except DnsTimeout as e:
        if i >= 10:
            return (-1, ['{}_timeout'.format(rs_type)])
        return resolving(host, resolver, rs_type, i+1)
    except NoAnswer as e:
        return (0, [])
    except NoNameservers as e:
        return (0, [])
    except EmptyLabel as e:
        return (0, [])
    except Exception as e:
        if 'The DNS query name does not exist: ' in str(e):
            return (0, [])
        raise e


def resolve(host, resolver):
    A = resolving(host, resolver)
    AAAA = resolving(host, resolver, "AAAA")

    if A[0] <=0 and AAAA[0] <= 0:
        return {"hostname": host, "found": int((A[0]+AAAA[0]-1)/2), 'IPs': A[1]+AAAA[1]}
    return {"hostname": host, "found": 1, 'IPs': list(set(A[1]+AAAA[1]))}


def get_info(dct):
    if dct['found']>0:
        return "HOST: {} has IPS:{}".format(dct["hostname"], ','.join(dct['IPs']))
    elif dct['found'] == 0:
        return "HOST: {} no IP found".format(dct["hostname"])
    return "HOST: {} resolution error: {}".format(dct["hostname"], dct['IPs'][0])

def resolve_hosts(hosts, domain, resolver, out_obj, max_thread=10):

    def verbose_thread(future):
        info=future.result()
        out_obj.out(get_info(info), info['found'] != 0 )

    thread_list = []
    out = []
    with ThreadPoolExecutor(max_workers=max_thread) as executor:
        for host in hosts:
            future = executor.submit(resolve, "{}.{}".format(host,domain), resolver)
            future.add_done_callback(verbose_thread)
            thread_list.append(future)

    for future in as_completed(thread_list):
        out.append(get_info(future.result()))
    return out


def init_resolve(domain, dns=[], port=53, verbose=True, file=False):
    resolver = Resolver()
    resolver.port=port
    if len(dns) > 0:
        resolver.nameservers=dns

    out_obj=Output(file, verbose)

    domaininfo=resolve(domain, resolver.resolve)
    if domaininfo['found'] <= 0:
        error("Error resolving domains:",[domain])
    
    out_obj.out(get_info(domaininfo))
    return (resolver, out_obj)

def resolve_file(domain, infile, dns=[], port=53, max_thread=10 , verbose=True, file=False):
    
    resolver, out_obj=init_resolve(domain, dns, port, verbose, file)

    try:
        with open(infile) as f:
            lines=True
            while lines!=[]:
                lines = [x.strip() for x in islice(f, 10*max_thread)]
                resolve_hosts(lines, domain, resolver.resolve, out_obj)

    except Exception as e:
        error("Error opening file:", [infile])

def resolve_brute(domain, dns=[], port=53, max_thread=10 , verbose=True, file=False):
    
    linker="-."    

    resolver, out_obj=init_resolve(domain, dns, port, verbose, file)

    prefix=''
    hosts=[]
    max_i=0
    
    def gen( prefix='', i=0):

        if len(hosts) >= 10*max_thread:
            resolve_hosts( hosts, domain, resolver.resolve, out_obj)
            hosts.clear()
            gen(prefix, i)
        else:
            for ch in list(ascii_lowercase+digits+("-." if i!=0 and prefix[-1]!="-" and prefix[-1]!="." and i<max_i-1 else "")) :
                hosts.append(prefix+ch)
                if i<max_i:
                    gen( prefix+ch, i+1)

    while True:
        gen()
        max_i+=1
