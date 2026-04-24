import sys
import os
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.contrib.igmp import IGMP
from scapy.all import *
from scapy import sendrecv, utils
import time
import collections
import argparse

#Diccionario que usaremos para rastrear la actividad
paquetes_syn = collections.defaultdict(list)

SYN_max = 20 #20 paquetes max
tiempo_sosp = 10 #Segundos que utilizaremos de referencia

IPs_sospechosas_syn = set()
def detect_syn_scan(paquete):
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
            if len(puertos) >= SYN_max:
                IPs_sospechosas_syn.add(IP_orig)


def captar_trafico(segundos):
    return sendrecv.sniff(timeout=segundos)

#Funcion para utilizar ver si te escanean el puerto
def filtrar_escaneo():
    sendrecv.sniff(filter="tcp", prn=detect_syn_scan, store=0, timeout=10)


def estadisticas_ips(paquetes):
    print("  - Estadísticas IP (origen o destino):")
    list_ip_pac = []
    for pac in paquetes:
        if pac.haslayer(IP):
            src = pac[IP].src
            dst = pac[IP].dst
            if list_ip_pac.count(src) == 0:
                list_ip_pac.append(pac[IP].src)
            elif list_ip_pac.count(dst) == 0:
                list_ip_pac.append(pac[IP].dst)

    for ip in list_ip_pac:
        contador = 0
        for paq in paquetes:
            if paq.haslayer(IP):
                if paq[IP].src == ip or paq[IP].dst == ip:
                    contador += 1
        print(f"    - IP {ip:<15}:\t{contador} paquetes")

def estadisticas_puertos(paquetes):
    print("  - Estadísticas de puertos:")
    puertos = collections.defaultdict(int)

    for pac in paquetes:
        if not(pac.haslayer(UDP) or pac.haslayer(TCP)):
            continue

        puertos[pac.sport] += 1
        puertos[pac.dport] += 1

    for puerto, cantidad in puertos.items():
        print(f"    - Puerto {puerto}:\t{cantidad} paquetes")

def estadisticas_protocolos(paquetes):
    print("  - Estadísticas de protocolos:")
    protocolos = {
        "ICMP": 0,
        "IGMP": 0,
        "TCP": 0,
        "UDP": 0,
        "OTROS": 0,
    }

    for paq in paquetes:
        if paq.haslayer(ICMP):
            protocolos["ICMP"] += 1
        elif paq.haslayer(IGMP):
            protocolos["IGMP"] += 1
        elif paq.haslayer(TCP):
            protocolos["TCP"] += 1
        elif paq.haslayer(UDP):
            protocolos["UDP"] += 1
        else:
            protocolos["OTROS"] += 1

    for protocolo, cantidad in protocolos.items():
        if cantidad == 0:
            continue
        print(f"    - Protocolo {protocolo}:\t{cantidad} paquetes")

def imprimir_estadisticas(paquetes):
    print("- Estadísticas generales:")
    estadisticas_ips(paquetes)
    estadisticas_puertos(paquetes)
    estadisticas_protocolos(paquetes)

def leer_captura(pcap_path):
    print(f"Leyendo archivo de captura \"{pcap_path}\". Esto podría tardar un poco...")

    paquetes = utils.rdpcap(pcap_path)

    for paquete in paquetes:
        detect_syn_scan(paquete)

    if len(IPs_sospechosas_syn) == 0:
        print("- SYN: No se han detectado ataques de escaneo SYN.")
    else:
        print(f"- SYN: Se han detectado {len(IPs_sospechosas_syn)} IPs sospechosas de escaneos SYN:")

        for ip in IPs_sospechosas_syn:
            print(f"  - {ip}:\tHa iniciado conexión con {len(paquetes_syn[ip])} puertos.")

    imprimir_estadisticas(paquetes)

def capturar_en_vivo():
    segundos_captura = 10
    print(f"Capturando tráfico en vivo durante {segundos_captura} segundos...")
    try:
        paquetes = captar_trafico(segundos_captura)
    except PermissionError:
        print("[ERROR] Debes de ejecutar el programa con privilegios de administrador para realizar la captura en vivo.")
        print("\tNota: Si estas utilizando un entorno virtual (como VirtualEnv/venv), asegúrate de utilizar \"sudo -E\" y colocar la ruta completa de tu intérprete Python (por ejemplo, \".venv/bin/python3\").")
        exit(1)

    print("Ahora tambien detectamos posibles escaneos: ")
    filtrar_escaneo()

    estadisticas_ips(paquetes)
    estadisticas_puertos(paquetes)
    estadisticas_protocolos(paquetes)

#///////////////////////////////////////////////////////////////////////
#MAIN
#///////////////////////////////////////////////////////////////////////
def main():
    parser = argparse.ArgumentParser(
        prog="Programa de captura y análisis de red",
    )

    parser.add_argument("-p", "--pcap")
    parser.add_argument("-c", "--capturar", action="store_true")
    args = parser.parse_args()

    paquetes = []

    if args.pcap is not None and args.capturar:
        print("[ERROR] Proveé un pcap o elige capturar en vivo, pero no ambos.")
        parser.print_help()
        return

    if args.pcap is not None:
        leer_captura(args.pcap)
        return

    if args.capturar:
        capturar_en_vivo()
        return

    print("[ERROR] No se ha elegido ninguna opcion.")
    parser.print_help()
    exit(1)

if __name__ == "__main__":
    main()
