from scapy.all import *


def imprimir_pacote(packet):
    if packet[ICMP].payload:
        print("\n{} ----ICMP----> {}:\n{}".format(packet[IP].src,
                                                         packet[IP].dst,
                                                         str(bytes(packet[ICMP].payload))))


sniff(filter='icmp', prn=imprimir_pacote, store=0, count=0)