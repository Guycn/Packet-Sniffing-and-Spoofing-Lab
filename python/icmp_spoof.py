#!/usr/bin/env python3
from scapy.all import *
 
print("SENDING SPOOFED ICMP PACKET..........")
a = IP()
a.src="10.0.2.4"
a.dst="10.0.2.6"     
b = ICMP()
pkt = a/b
pkt.show()
send(pkt,verbose=0)
