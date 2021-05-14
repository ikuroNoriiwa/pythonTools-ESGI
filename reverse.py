#!/usr/bin/python3

from dns.reversename import from_address
from dns.resolver import Resolver
from dns.exception import Timeout as DnsTimeout
from dns.resolver import NoAnswer
from dns.name import EmptyLabel
from concurrent.futures import as_completed, ThreadPoolExecutor
from tools import error, Output



def reverse_resolve(ip, resolver, i=0):
    ip_name=from_address(str(ip))
    try:
        return {"IP": str(ip), "found": 1, "hostname": list(map(str,resolver(ip_name, "PTR")))}

    except DnsTimeout as e:
        if i >= 10:
            return {"IP": str(ip), "found": -1, "hostname": "timeout"}
        return reverse_resolve(ip, resolver, i+1)
    except NoAnswer as e:
            return {"IP": str(ip), "found": 0, "hostname": "notexist"}
    except EmptyLabel as e:
            return {"IP": str(ip), "found": 0, "hostname": "notexist"}
    except Exception as e:
        if 'The DNS query name does not exist: ' in str(e):
            return {"IP": str(ip), "found": 0, "hostname": "notexist"}
        raise e

def get_info(dct):
    if dct['found']:
        return "IP: {} has PTR:{}".format(dct["IP"], ','.join(dct['hostname']))
    return "IP: {} PTR not found reason:{}".format(dct["IP"], dct['hostname'])

def range_ip(lowest_address, higher_address, dns=[], port=53, max_thread=10 , verbose=True, file=False):
    resolver = Resolver()
    resolver.port=port
    if len(dns) > 0:
        resolver.nameservers=dns

    out_obj=Output(file, verbose)

    def verbose_thread(future):
        out_obj.out(get_info(future.result()), future.result()['found']!=0)

    thread_list = []
    out = []
    with ThreadPoolExecutor(max_workers=max_thread) as executor:
        while lowest_address <= higher_address:
            future = executor.submit(reverse_resolve, lowest_address, resolver.resolve)
            if verbose:
                future.add_done_callback(verbose_thread)
            thread_list.append(future)
            lowest_address = lowest_address + 1

    for future in as_completed(thread_list):
        out.append(get_info(future.result()))
    return out
