from scapy.all import *
from collections import *
import time

#Diccionario que usaremos para rastrear la actividad
paquetes_syn = defaultdict(list)

SYN_max = 20 #20 paquetes max
tiempo_sosp = 10 #Segundos que utilizaremos de referencia

def detect_syn_scan(paquete):
    IPs_alertadas = set()
    
    if paquete.haslayer(TCP) and paquete.haslayer(IP):
        cab_TCP = paquete[TCP]
        cab_IP = paquete[IP]

        if cab_TCP.flags == "S":
            IP_orig = cab_IP.src
            tiempo_act = time.time()

            #Metemos en la lista los paquetes SYN
            paquetes_syn[IP_orig].append((cab_TCP.dport, tiempo_act))

            #FIltramos en funcion del tiempo, nos quedamos con los sospechosos
            paquetes_syn[IP_orig] = [
                (port, t) for port, t in paquetes_syn[IP_orig]
                if tiempo_act - t <= tiempo_sosp
            ]

            puertos = {port for port, _ in paquetes_syn[IP_orig]}

            #SI cumple las condiciones, el paquete es sospechoso
            if len(puertos) >= SYN_max and IP_orig not in IPs_alertadas:
                print(f"Alerta, posible escaneo de puertos desde la direccion: {IP_orig} ")
                print(f"Puertos detectados: {sorted(puertos)}")

                #Esto es para no repetir la misma respuesta 1 millon de veces
                IPs_alertadas.add(IP_orig)


def captar_trafico():
    return sniff(timeout=10)

#Funcion para utilizar ver si te escanean el puerto
def filtrar_escaneo():
    sniff(filter="tcp", prn=detect_syn_scan, store=0)
    #Store = 0, no se guarda en ningun lado

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


#///////////////////////////////////////////////////////////////////////
#MAIN
#///////////////////////////////////////////////////////////////////////
        


opcion = sys.argv[1]

seleccion = sys.argv[2]

paquetes = []

if opcion == "1":
    print("Has elegido la opcion de: CAPTAR TRAFICO")
    paquetes = captar_trafico()
    print("Ahora tambien detectamos posibles escaneos: ")
    filtrar_escaneo()

    estadisticas_ips(paquetes)

    estadisticas_puertos(paquetes)

    estadisticas_protocolos(paquetes)
    
elif opcion == "2":
    print("Si has elegido esta opcion [2], es normal que tarde mucho")
    paquetes = rdpcap(seleccion)
    print("Has elegido la opcion de: LEER ARCHIVO")
    for paquete in paquetes:
        detect_syn_scan(paquete)

    estadisticas_ips(paquetes)

    estadisticas_puertos(paquetes)

    estadisticas_protocolos(paquetes)
    
else:
    print("Lo sentimos, pero esta opcion no es valida")
    print("////////////////////////////////////////////////////")
    print("Guia: ")
    print("Para capturar el trafico: [1] como primer parametro ")
    print("Para leer un archivo: [2] como primer parametro ")

