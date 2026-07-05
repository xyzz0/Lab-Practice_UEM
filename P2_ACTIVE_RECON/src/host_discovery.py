#!/usr/bin/env python3

from scapy.all import IP, TCP, UDP, ICMP, sr

PROTOS_VALIDOS = {"UDP", "TCP", "ICMP"}


def craft_discovery_pkts(protocolos, objetivos, num_pkts=None, puerto=80):

    if isinstance(protocolos, str):
        protocolos = [protocolos]
    protocolos = [p.upper() for p in protocolos]

    for p in protocolos:
        if p not in PROTOS_VALIDOS:
            raise ValueError(f"Protocolo no válido: {p} (usa {PROTOS_VALIDOS})")

    if num_pkts is None:
        num_pkts = {}

    paquetes = []
    for proto in protocolos:
        cantidad = num_pkts.get(proto, 1)
        for _ in range(cantidad):
            if proto == "ICMP":
                pkt = IP(dst=objetivos) / ICMP(type=13)
            elif proto == "TCP":
                pkt = IP(dst=objetivos) / TCP(dport=puerto, flags="A")
            else:  # UDP
                pkt = IP(dst=objetivos) / UDP(dport=puerto)
            paquetes.append(pkt)
    return paquetes


def hosts_activos(respuestas):
    """Extrae el conjunto de IPs que han respondido (host vivo)."""
    return {recibido.src for _, recibido in respuestas}


if __name__ == "__main__":
    HOST_ACTIVO   = "172.28.0.10"
    HOST_INACTIVO = "172.20.0.99"

    pkts_vivo = craft_discovery_pkts(
        ["ICMP", "TCP", "UDP"], HOST_ACTIVO,
        num_pkts={"ICMP": 1, "TCP": 1, "UDP": 1}, puerto=80,
    )

    pkts_muerto = craft_discovery_pkts("ICMP", HOST_INACTIVO)

    todos = pkts_vivo + pkts_muerto
    print(f"[*] Enviando {len(todos)} paquetes...")

    ans, unans = sr(todos, timeout=2, verbose=0)
    print(f"[+] Hosts activos detectados: {len(activos)}")
    for ip in sorted(activos):
        print(f"    {ip}")

    if not activos:
        print("[-] Nadie respondió (¿firewall, permisos root o ICMP filtrado?)")

