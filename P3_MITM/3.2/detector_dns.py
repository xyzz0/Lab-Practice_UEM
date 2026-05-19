#!/usr/bin/env python3

from scapy.all import sniff, IP, UDP, DNS, DNSQR, DNSRR
from collections import defaultdict
import time
import threading
import re

# ── Parámetros de umbral ──────────────────────────────────────────────────────
UMBRAL_QUERIES   = 10    # nº de consultas distintas en la ventana → alerta
VENTANA_SEG      = 5     # ventana deslizante en segundos
UMBRAL_NXDOMAIN  = 5     # nº de NXDOMAINs por IP en la ventana → alerta
DOMINIO_BASE     = "practica.local"

# ── Estado del IDS ────────────────────────────────────────────────────────────
# ip → lista de timestamps de queries
queries_por_ip: dict[str, list] = defaultdict(list)
# ip → lista de (timestamp, qname) de NXDOMAINs
nxdomain_por_ip: dict[str, list] = defaultdict(list)
# qnames pendientes de resolución: id_transaccion → qname
pending_queries: dict[int, tuple] = {}  # txid → (ip_src, qname, timestamp)
lock = threading.Lock()

# ── Colores ANSI ──────────────────────────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

BANNER = f"""
{CYAN}╔══════════════════════════════════════════════════════════╗
║       DETECTOR DNS SNOOPING / KAMINSKY — Scapy IDS       ║
║  Firma 1 : Threshold de queries por IP (volumen)          ║
║  Firma 2 : Ráfaga de NXDOMAINs (subdominios inexistentes) ║
║  Firma 3 : Prefijos aleatorios → patrón Kaminsky          ║
╚══════════════════════════════════════════════════════════╝{RESET}
"""

def ts() -> str:
    return time.strftime("%H:%M:%S")


def ventana_activa(eventos: list, ahora: float) -> list:
    return [t for t in eventos if ahora - t <= VENTANA_SEG]


def parece_aleatorio(subdominio: str, min_len: int = 6) -> bool:
    if len(subdominio) < min_len:
        return False
    vocales = sum(1 for c in subdominio.lower() if c in "aeiou")
    digitos = sum(1 for c in subdominio if c.isdigit())
    # Ratio bajo de vocales o muchos dígitos → sospechoso
    ratio_vocales = vocales / max(len(subdominio), 1)
    return ratio_vocales < 0.15 or digitos > len(subdominio) * 0.4


def alert_dnssnooping(pkt) -> None:
    if not (pkt.haslayer(IP) and pkt.haslayer(DNS)):
        return

    dns  = pkt[DNS]
    ip   = pkt[IP]
    ahora = time.time()

    with lock:

        # ── Procesar DNS Query (qr=0) ─────────────────────────────────────────
        if dns.qr == 0 and dns.qdcount > 0:
            qname = dns[DNSQR].qname.decode(errors="replace").rstrip(".")
            ip_src = ip.src
            txid   = dns.id

            # Guardar query pendiente para cruzarla con la respuesta
            pending_queries[txid] = (ip_src, qname, ahora)

            # Registrar timestamp de query
            queries_por_ip[ip_src].append(ahora)
            queries_por_ip[ip_src] = ventana_activa(queries_por_ip[ip_src], ahora)

            # ── Firma 1: Umbral de volumen de queries ─────────────────────────
            n_queries = len(queries_por_ip[ip_src])
            if n_queries >= UMBRAL_QUERIES:
                print(
                    f"{RED}{BOLD}[{ts()}] ⚠  ALERTA — Firma 1: UMBRAL DE QUERIES SUPERADO{RESET}\n"
                    f"  IP origen : {ip_src}\n"
                    f"  Queries   : {n_queries} en los últimos {VENTANA_SEG}s\n"
                    f"  Última    : {qname}\n"
                )

            # ── Firma 3: Prefijo aleatorio (Kaminsky) ─────────────────────────
            partes = qname.split(".")
            if len(partes) >= 3:
                subdominio = partes[0]
                dominio    = ".".join(partes[1:])
                if DOMINIO_BASE in dominio and parece_aleatorio(subdominio):
                    print(
                        f"{YELLOW}[{ts()}] ⚠  ALERTA — Firma 3: PREFIJO ALEATORIO (Kaminsky){RESET}\n"
                        f"  IP origen    : {ip_src}\n"
                        f"  Subdominio   : {subdominio}  ← parece generado aleatoriamente\n"
                        f"  FQDN         : {qname}\n"
                    )

        # ── Procesar DNS Response (qr=1) ──────────────────────────────────────
        elif dns.qr == 1:
            txid = dns.id
            rcode = dns.rcode  # 3 = NXDOMAIN

            if txid in pending_queries:
                ip_src, qname, _ = pending_queries.pop(txid)

                if rcode == 3:  # NXDOMAIN
                    nxdomain_por_ip[ip_src].append((ahora, qname))
                    # Mantener solo eventos en la ventana
                    nxdomain_por_ip[ip_src] = [
                        (t, q) for t, q in nxdomain_por_ip[ip_src]
                        if ahora - t <= VENTANA_SEG
                    ]

                    n_nx = len(nxdomain_por_ip[ip_src])

                    # ── Firma 2: Ráfaga de NXDOMAINs ─────────────────────────
                    if n_nx >= UMBRAL_NXDOMAIN:
                        dominios = [q for _, q in nxdomain_por_ip[ip_src]]
                        print(
                            f"{RED}{BOLD}[{ts()}] ⚠  ALERTA — Firma 2: RÁFAGA DE NXDOMAIN{RESET}\n"
                            f"  IP origen   : {ip_src}\n"
                            f"  NXDOMAINs   : {n_nx} en los últimos {VENTANA_SEG}s\n"
                            f"  Subdominios : {dominios[-5:]}\n"
                            f"  Posible DNS Snooping / ataque de Kaminsky\n"
                        )
                    else:
                        print(
                            f"{GREEN}[{ts()}] NXDOMAIN #{n_nx:2d} | {ip_src} → {qname}{RESET}"
                        )


def limpiar_pendientes(intervalo: int = 15) -> None:
    while True:
        time.sleep(intervalo)
        ahora = time.time()
        with lock:
            expirados = [txid for txid, (_, _, t) in pending_queries.items()
                         if ahora - t > 30]
            for txid in expirados:
                del pending_queries[txid]


if __name__ == "__main__":
    print(BANNER)
    print(f"{CYAN}[*] Escuchando tráfico DNS en todas las interfaces...{RESET}")
    print(f"    Umbral queries : {UMBRAL_QUERIES} en {VENTANA_SEG}s")
    print(f"    Umbral NXDOMAIN: {UMBRAL_NXDOMAIN} en {VENTANA_SEG}s\n")

    t = threading.Thread(target=limpiar_pendientes, daemon=True)
    t.start()

    sniff(
        filter="udp port 53",
        prn=alert_dnssnooping,
        store=False,
        iface=None
    )
