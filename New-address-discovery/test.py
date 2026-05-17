from scapy.all import *
pkt = IPv6(dst="2402:f000:6:1e00::233")/ICMPv6EchoRequest()
send(pkt, iface="ens17f0")