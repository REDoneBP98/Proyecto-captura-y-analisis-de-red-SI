from scapy.all import sniff, wrpcap

#captura de 30 paquetes de la red
packages = sniff(timeout=20)
#o count=50 (paquetes)

print('Capturando paquetes de la red...')

#Ahora lo guaramos en un archivo
wrpcap('captura.pcap', packages)

#Confirmacion
print('Se ha guardado la captura en el archivo captura.pcap')
