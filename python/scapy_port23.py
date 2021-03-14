#!/usr/bin/env python3
from scapy.all import*


def print_pkt(pkt):
	pkt.show()
pkt = sniff(iface = ["br-d573fd93a01e", "enp0s3"], 
filter = "tcp and(src 10.0.2.5 and port 23)"
 , prn = print_pkt)
