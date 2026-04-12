from scapy.all import *


def estadisticas_ips(paquetes):

    list_ip_pac = []

    print("Analizando paquetes...")
    
    for pac in paquetes:
        if pac.haslayer(IP):
            src = pac[IP].src
            dst = pac[IP].dst
            if list_ip_pac.count(src) == 0:
                list_ip_pac.append(pac[IP].src)
            elif list_ip_pac.count(dst) == 0:
                list_ip_pac.append(pac[IP].dst)

    print("Lista de paquetes leidos, generando resultados...")
                
    for ip in list_ip_pac:
        contador = 0
        for paq in paquetes:
            if paq.haslayer(IP):
                if paq[IP].src == ip or paq[IP].dst == ip:
                    contador += 1
        print("Pquetes con IP " + ip + " = " + str(contador))
        

paquetes = rdpcap("http.cap")

estadisticas_ips(paquetes)
