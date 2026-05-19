#!/usr/bin/env python3

from scapy.all import sniff, ARP, Ether
from collections import defaultdict
import time
import threading

arp_table: dict[str, str] = {}
pending_requests: dict[str, float] = {}
lock = threading.Lock()

RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
RESET  = "\033[0m"

BANNER = f"""
{CYAN}=====================================================
===        DETECTOR ARP SPOOFING  â€” Scapy IDS           |
===  Firma 1 : MAC-IP incongruente                        |
===  Firma 2 : Gratuitous ARP sospechoso                  |
===  Firma 3 : ARP reply no solicitado                    |
=======================================================
"""

def ts() -> str:
    """Timestamp legible."""
    return time.strftime("%H:%M:%S")


def alert_arpspoof(pkt) -> None:

    # Solo nos interesan paquetes con capa ARP
    if not pkt.haslayer(ARP):
        return

    arp = pkt[ARP]
    src_ip  = arp.psrc   # IP del que envia
    src_mac = arp.hwsrc  # MAC del que e­via
    dst_ip  = arp.pdst   # IP consultada / destino
    op      = arp.op     # 1=who-has (request), 2=is-at (reply)

    with lock:

        if op == 1:  # ARP Request
            pending_requests[dst_ip] = time.time()
            return  

        if src_ip in arp_table:
            known_mac = arp_table[src_ip]
            if known_mac != src_mac:
                print(
                    f"{RED}[{ts()}]    ALERTA ” Firma 1: MAC-IP INCONGRUENTE{RESET}\n"
                    f"  IP      : {src_ip}\n"
                    f"  MAC prev: {known_mac}\n"
                    f"  MAC nueva: {src_mac}  SOSPECHOSA\n"
                    f"  Posible atacante realizando ARP Spoofing / MITM\n"
                )
        else:
            # Primera vez que vemos esta IP â†’ la registramos
            arp_table[src_ip] = src_mac
            print(f"{GREEN}[{ts()}] ”  Nueva entrada ARP: {src_ip} ’ {src_mac}{RESET}")

        if src_ip == dst_ip:
            print(
                f"{YELLOW}[{ts()}]    ALERTA ” Firma 2: GRATUITOUS ARP SOSPECHOSO{RESET}\n"
                f"  {src_mac} anuncia que posee {src_ip} sin ser preguntado.\n"
                f"  Esto puede indicar envenenamiento de cachÃ© ARP masivo.\n"
            )

        request_time = pending_requests.get(src_ip)
        window = 5.0

        if request_time is None:
            print(
                f"{YELLOW}[{ts()}]    ALERTA ” Firma 3: REPLY NO SOLICITADO{RESET}\n"
                f"  {src_mac} Envia  ARP reply para {src_ip}\n"
                f"  sin que exista ningun ARP request previo registrado.\n"
            )
        elif time.time() - request_time > window:
            print(
                f"{YELLOW}[{ts()}]    ALERTA ” Firma 3: REPLY Tardio (ventana {window}s superada){RESET}\n"
                f"  {src_mac} responde por {src_ip} {time.time()-request_time:.1f}s"
                f" Despues del request.\n"
            )
        else:
            
            del pending_requests[src_ip]


def limpiar_pendientes(intervalo: int = 10) -> None:
    """Hilo auxiliar: purga requests mÃ¡s antiguos que 30 s."""
    while True:
        time.sleep(intervalo)
        ahora = time.time()
        with lock:
            expirados = [ip for ip, t in pending_requests.items() if ahora - t > 30]
            for ip in expirados:
                del pending_requests[ip]


if __name__ == "__main__":
    print(BANNER)
    print(f"{CYAN}[*] Iniciando monitorizaciónn ARP en todas las interfaces...{RESET}\n")

    # Hilo de limpieza de tabla de requests
    t = threading.Thread(target=limpiar_pendientes, daemon=True)
    t.start()

    # Captura continua, filtrando solo paquetes ARP
    sniff(
        filter="arp",
        prn=alert_arpspoof,
        store=False,
        iface="br-5abcc0f65712"
    )

