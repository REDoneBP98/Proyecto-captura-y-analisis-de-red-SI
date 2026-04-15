from scapy.all import *

def captar_trafico():
    return sniff(timeout=10)

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

def estadisticas_puertos(paquetes):
    print("-----------------------------------------")
    print("A continuacion los puertos detectados")
    
    list_port_pac = []
    
    cont_UDP = 0
    cont_TCP = 0

    for pac in paquetes:
        if pac.haslayer(UDP):
            UDP_S = pac[UDP].sport
            UDP_D = pac[UDP].dport
            cont_UDP += 1
            if list_port_pac.count(UDP_S) == 0:
                list_port_pac.append(UDP_S)
            elif list_port_pac.count(UDP_D) == 0:
                list_port_pac.append(UDP_D)        
        elif pac.haslayer(TCP):
            TCP_S = pac[TCP].sport
            TCP_D = pac[TCP].dport
            cont_TCP += 1
            if list_port_pac.count(TCP_S) == 0:
                list_port_pac.append(TCP_S)
            elif list_port_pac.count(TCP_D) == 0:
                list_port_pac.append(TCP_D)
            
    for prt in list_port_pac:
        contador = 0
        for paq in paquetes:
            if paq.haslayer(UDP):
                if paq[UDP].sport == prt or paq[UDP].dport == prt:
                    contador += 1
            elif paq.haslayer(TCP):
                if paq[TCP].sport == prt or paq[TCP].dport == prt:
                    contador += 1
                
        print("Paquetes con el puerto " + str(prt) + " ==> " + str(contador))
    print("-----------------------------------------")
    print("Y paquetes con UDP = " + str(cont_UDP) + " / y TCP = " + str(cont_TCP))


def estadisticas_protocolos(paquetes):

    print("-----------------------------------------")
    list_prot_pac = []

    for pac in paquetes:
        if pac.haslayer(IP) and pac.haslayer(UDP):
            if list_prot_pac.count(pac[IP].proto) == 0:
                list_prot_pac.append(pac[IP].proto)
        elif pac.haslayer(IP) and pac.haslayer(TCP):
            if list_prot_pac.count(pac[IP].proto) == 0:
                list_prot_pac.append(pac[IP].proto)
        elif pac.haslayer(IP) and pac.haslayer(ICMP):
            if list_prot_pac.count(pac[IP].proto) == 0:
                list_prot_pac.append(pac[IP].proto)
        elif pac.haslayer(IP) and pac.haslayer(IGMP):
            if list_prot_pac.count(pac[IP].proto) == 0:
                list_prot_pac.append(pac[IP].proto)

    #Listado de protocolos
    #ICMP = 1 // TCP = 6 // UDP = 17 // IGMP = 2


    for prot in list_prot_pac:

        protocolo = ""
        contador = 0
        
        if prot == 17:
            protocolo = "UDP"
        elif prot == 6:
            protocolo = "TCP"
        elif prot == 1:
            protocolo = "ICMP"
        elif prot == 2:
            protocolo = "IGMP"
        else:
            protocolo = "desconocido"
        
        for paq in paquetes:
            if paq.haslayer(UDP) and paq.haslayer(IP):
                if paq[IP].proto == prot:
                    contador += 1
            elif paq.haslayer(TCP) and paq.haslayer(IP):
                if paq[IP].proto == prot:
                    contador += 1
            elif paq.haslayer(ICMP) and paq.haslayer(IP):
                if paq[IP].proto == prot:
                    contador += 1
            elif paq.haslayer(IGMP) and paq.haslayer(IP):
                if paq[IP].proto == prot:
                    contador += 1
                
        print("Paquetes con el protocolo: " + protocolo + " ==> " + str(contador))
        
        

opcion = sys.argv[1]

seleccion = sys.argv[2]

paquetes = []

if opcion == "1":
    print("Has elegido la opcion de: CAPTAR TRAFICO")
    paquetes = captar_trafico()
if opcion == "2":
    paquetes = rdpcap(seleccion)
    print("Has elegido la opcion de: LEER ARCHIVO")


estadisticas_ips(paquetes)

estadisticas_puertos(paquetes)

estadisticas_protocolos(paquetes)
