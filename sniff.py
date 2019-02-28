from scapy.all import *

def pkt_callback(pkt):
    pkt.show() # debug statement

sniff(iface="Wi-Fi", prn=pkt_callback, filter="tcp", store=0)