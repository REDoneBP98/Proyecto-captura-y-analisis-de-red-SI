from scapy.all import *

paquetes = rdpcap("captura.pcap")

print(len(paquetes))
print(paquetes[0].summary())
