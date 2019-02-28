from scapy.all import *


def process_tcp_packet(packet):
    '''
    Processes a TCP packet, and if it contains an HTTP request, it prints it.
    '''
    if not packet.haslayer('HTTPRequest'):
        # This packet doesn't contain an HTTP request so we skip it
        return
    http_layer= packet.getlayer('HTTPRequest').fields
    ip_layer = packet.getlayer('IP').fields
    print('\n{0[src]} just requested a {1[Method]} {1[Host]}{1[Path]}'.format(ip_layer,http_layer))
    print('\n{0[src]} just requested a {1[Method]} {1[Host]}{1[Path]}'.format(ip_layer.fields, http_layer.fields))

# Start sniffing the network.
sniff(filter='tcp', prn=process_tcp_packet)