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
    if p.poll():
        # print(str(ip)+" is down", file=stderr)
        dct = {"IP": str(ip), "is_alive": False}
    else:
        # print(str(ip)+" is up", file=stderr)
        dct = {"IP": str(ip), "is_alive": True}

    return dct


def range_ip(lowest_address, higher_address, max_thread=10):
    """
    Lance dans un ping toutes les IPs
    :param lowest_address: Première adresse de la série à scanner
    :param higher_address: Dernière adresse de la série à scanner
    :param max_thread: Nombre de Thread à utliser dans le scan (augmente la consommation de ressources)
    :return: None
    """
    thread_list = []
    out = []
    with ThreadPoolExecutor(max_workers=max_thread) as executor:
        while lowest_address <= higher_address:
            future = executor.submit(ping, lowest_address)
            thread_list.append(future)
            lowest_address = lowest_address + 1

    for i in as_completed(thread_list):
        info=""
        if i.result()['is_alive'] is True:
            info="{:15s} is up".format(i.result()['IP'])
        else:
            info="{:15s} is down".format(i.result()['IP'])
        print(info)
        out.append(info)
    return out