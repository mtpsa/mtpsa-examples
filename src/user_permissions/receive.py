#!/usr/bin/env python
import sys

from scapy.all import sniff, get_if_list

def get_if():
    interfaces = get_if_list()
    for i in interfaces:
        if "eth0" in i:
            return i
    print("Cannot find eth0 interface")
    sys.exit(1)

def handle_pkt(pkt):
    pkt.show2()

def main():
    iface = get_if()
    print("sniffing on %s" % iface)
    sniff(filter="ip and ( tcp or udp )", iface=iface, prn=handle_pkt)

if __name__ == '__main__':
    main()
