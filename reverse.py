#!/usr/bin/python3

from os import error
from dns.reversename import from_address
from dns.resolver import Resolver
from dns.exception import Timeout as DnsTimeout
from concurrent.futures import as_completed, ThreadPoolExecutor




def reverse_resolve(ip, resolve, i=0):
    ip_name=from_address(str(ip))
    try:
        return {"IP": str(ip), "found": True, "hostname": resolve(ip_name, "PTR")[0]}

    except DnsTimeout as e:
        if i >= 10:
            return {"IP": str(ip), "found": False, "hostname": "timeout"}
        return reverse_resolve(ip, resolve, i+1)
    except Exception as e:
        if 'The DNS query name does not exist: ' in str(e):
            return {"IP": str(ip), "found": False, "hostname": "notexist"}
        raise e

def get_info(dct):
    if dict['found']:
        return "IP: {} has PTR:{}".format(dct["IP"], dct['hostname'])
    return "IP: {} PTR not found reason:{}".format(dct["IP"], dct['hostname'])

def verbose_thread(future):
    print(get_info(future.result()))

def range_ip(lowest_address, higher_address, dns=[], port=53, max_thread=10 , verbose=True):
    resolve = Resolver()
    resolve.port=port
    if len(dns) > 0:
        resolve.nameservers=dns


    thread_list = []
    out = []
    with ThreadPoolExecutor(max_workers=max_thread) as executor:
        while lowest_address <= higher_address:
            future = executor.submit(reverse_resolve, lowest_address, resolve.resolve)
            if verbose:
                future.add_done_callback(verbose_thread)
            thread_list.append(future)
            lowest_address = lowest_address + 1

    for future in as_completed(thread_list):
        out.append(get_info(future.result()))
    return out