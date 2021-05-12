#!/usr/bin/python3
from ipaddress import ip_address
from subprocess import PIPE, Popen
from concurrent.futures import as_completed, ThreadPoolExecutor
from platform import system
from os import devnull
from sys import stderr

__OS__ = system()


def ping(ip):
    """
    Utilise le binaire ping pour savoir si une machine répond
    :param ip: ipaddress.ip_address : adresse IP à scanner
    :return: dict{"IP": ip, "is_alive": False/True} : Dictionnaire avec l'IP et le retour du ping (False si ne répond
    pas, True si Répond)
    """
    if __OS__ == "Linux" or __OS__ == "Darwin":
        p = Popen(['ping', '{}'.format(str(ip)), "-c2", "-W1", "-b", "-4"], stdout=PIPE, stderr=open(devnull, 'w'))
    else:
        p = Popen(['ping', '{}'.format(str(ip)), "-n", "2", "-4"], stdout=PIPE, stderr=open(devnull, 'w'))
    p.wait()
    
    dct = {"IP": str(ip), "is_alive": not p.poll()}

    return dct

def get_info(dct):
    return "{:15s} is {}".format(dct['IP'], 'up' if  dct['is_alive']else 'down')

def verbose_thread(future):
    print(get_info(future.result()))


def range_ip(lowest_address, higher_address, max_thread=10, verbose=True):
    """
    Lance dans un ping toutes les IPs
    :param lowest_address: Première adresse de la série à scanner
    :param higher_address: Dernière adresse de la série à scanner
    :param max_thread: Nombre de Thread à utliser dans le scan (augmente la consommation de ressources)
    :return: None
    """
    thread_list = []
    thread_list_ever_complited = []
    out = []
    with ThreadPoolExecutor(max_workers=max_thread) as executor:
        while lowest_address <= higher_address:
            future = executor.submit(ping, lowest_address)
            if verbose:
                future.add_done_callback(verbose_thread)
            thread_list.append(future)
            lowest_address = lowest_address + 1

    for future in as_completed(thread_list):
        out.append(get_info(future.result()))
    return out