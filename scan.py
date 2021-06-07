#!/bin/python3

import sys
import socket
from datetime import datetime


def scan_ip(ip):
    
    if len(sys.argv) == 4:
        target = socket.gethostbyname(sys.argv[3]) # Translate hostname to ipv4
    else:
        print("Invalid amout of argument.")
        print("\n Syntax : python3 main.py scan --net <ip>")
	
    #Add a pretty banner
    print("-" * 50)
    print("Scanning target "+target)
    print("Time started: "+str(datetime.now()))
    print("-" * 50)

    try:
        for port in range(1,65535):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)
            result = s.connect_ex((target,port)) #returns an error indicator
            if result == 0:
                print("{} open".format(port))
            s.close()
		
    except KeyboardInterrupt:
        print("\nExiting program.")
        sys.exit()

    except socket.gaierror:
        print("Hostname could not be resolved.")
	
    except socket.error:
        print("Couldn't connect to server.")
        sys.exit()
        
