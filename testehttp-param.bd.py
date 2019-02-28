from scapy.all import *
import postgresql

db = postgresql.open("pq://postgres:123456@localhost/security")
statement = db.prepare("insert into ips (from_ip, to_ip, protocol_ip) values ($1, $2, $3)")

dsts = []

def imprimir_pacote(packet):
    if packet[TCP].payload:
        if packet[IP].dport == 80:
            dst = packet[IP].dst
            if dst not in dsts:
                dsts.append(dst)
                statement(packet[IP].src, dst, 'HTTP')

            print("\n{} ----HTTP----> {}:{}:\n{}".format(packet[IP].src,
                                                         dst,
                                                         packet[IP].dport, 
                                                         str(bytes(packet[TCP].payload))))


sniff(filter='tcp', prn=imprimir_pacote, store=0, count=0)