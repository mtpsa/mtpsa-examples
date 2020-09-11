#!/usr/bin/env python
import sys
import socket
import random

from scapy.all import sendp, get_if_list, get_if_hwaddr
from scapy.all import Ether, IP, TCP

def get_if():
    ifs = get_if_list()
    for i in ifs:
        if "eth0" in i:
            return i
    print("Cannot find eth0 interface")
    sys.exit(1)

def main():
    if len(sys.argv) < 3:
        print('Usage: %s <destination> "<message>"' % sys.argv[0])
        sys.exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()

    print("sending on interface %s to %s" % (iface, str(addr)))
    pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff') / IP(dst=addr)
    pkt /= TCP(dport=1234, sport=random.randint(49152, 65535)) / sys.argv[2]
    pkt.show2()
    sendp(pkt, iface=iface, verbose=False)

if __name__ == '__main__':
    main()
