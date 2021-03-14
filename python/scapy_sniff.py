#!/usr/bin/env python3
from scapy.all import*


def print_pkt(pkt):
	pkt.show()
	

pkt = sniff(iface = ["br-d573fd93a01e", "enp0s3"], filter = "icmp" , prn = print_pkt)
