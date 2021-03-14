#!/usr/bin/env python3
from scapy.all import *
 
a = IP()
a.src="10.0.2.4"
a.dst="10.0.2.6"   
a.ttl = 1  
b = ICMP()
while 1:
	pkt = a/b
	pkt.show()
	send(pkt,verbose=0)
	a.ttl+=1
