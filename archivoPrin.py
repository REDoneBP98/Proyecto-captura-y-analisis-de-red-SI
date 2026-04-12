from scapy.all import *

#Capturando duarante 20 seg, timeout=20
packets = sniff(timeout=10)
#o count=50 (paquetes)


#Ahora lo guaramos en un archivo
wrpcap('captura.pcap', packets)

print(len(packets))

#Confirmacion
print('Se ha guardado la captura en el archivo captura.pcap')

show_interfaces()

paquetes = rdpcap("http.cap")

#Ahora podemos intentar hacer algo diferente
for pac in paquetes:
	if pac.haslayer(IP):
                src = pac[IP].src
                dst = pac[IP].dst
                

#En teoria muestra un listado de paquetes
print(len(paquetes))
print(paquetes[0].display())
