from scapy.all import *

#Capturando duarante 20 seg, timeout=20
paquetes = sniff(timeout=10)
#o count=50 (paquetes)


#Ahora lo guaramos en un archivo
wrpcap('captura.pcap', paquetes)

print(len(paquetes))

#Confirmacion
print('Se ha guardado la captura en el archivo captura.pcap')

show_interfaces()
