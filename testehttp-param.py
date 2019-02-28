from scapy.all import *


def imprimir_pacote(packet):
    if packet[TCP].payload:
        if packet[IP].dport == 80:
            print("\n{} ----HTTP----> {}:{}:\n{}".format(packet[IP].src,
                                                         packet[IP].dst,
                                                         packet[IP].dport, 
                                                         str(bytes(packet[TCP].payload))))


sniff(filter='tcp', prn=imprimir_pacote, store=0, count=0)