#!/usr/bin/env python3
from scapy.all import IP, UDP, DNS, DNSQR, sr1, send
import random
import string
import time

# ── Configuración ─────────────────────────────────────────────────────────────
DNS_RESOLVER_IP = "172.20.0.20"   # nodo dns_resolver
DNS_SERVER_IP   = "172.20.0.10"   # servidor DNS autoritativo
DOMINIO_BASE    = "practica.local"
IFACE           = "eth0"

# ── Colores ───────────────────────────────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
RESET  = "\033[0m"


def random_subdomain(length: int = 10) -> str:
    consonantes = "bcdfghjklmnpqrstvwxyz0123456789"
    return "".join(random.choices(consonantes, k=length))


def dns_query(qname: str, dst_ip: str, verbose: bool = True) -> None:
    pkt = (
        IP(dst=dst_ip) /
        UDP(sport=random.randint(1024, 65535), dport=53) /
        DNS(rd=1, qd=DNSQR(qname=qname))
    )
    resp = sr1(pkt, iface=IFACE, timeout=2, verbose=False)

    if verbose:
        if resp and resp.haslayer(DNS):
            rcode = resp[DNS].rcode
            estado = {0: f"{GREEN}NOERROR{RESET}",
                      3: f"{RED}NXDOMAIN{RESET}"}.get(rcode, f"rcode={rcode}")
            print(f"  [{estado}] {qname}")
        else:
            print(f"  [{YELLOW}TIMEOUT{RESET}] {qname}")


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":

    print(f"\n{CYAN}╔══════════════════════════════════════════════════════╗")
    print(f"║    GENERADOR DE TRÁFICO DNS — Simulación Kaminsky    ║")
    print(f"╚══════════════════════════════════════════════════════╝{RESET}\n")

    # ── Fase 1: Tráfico legítimo (no debe disparar alertas) ──────────────────
    print(f"{GREEN}[FASE 1] Consultas legítimas (tráfico normal)...{RESET}")
    legítimas = [
        f"www.{DOMINIO_BASE}",
        f"mail.{DOMINIO_BASE}",
        f"vpn.{DOMINIO_BASE}",
        "google.com",
        "github.com",
    ]
    for dominio in legítimas:
        dns_query(dominio, DNS_RESOLVER_IP)
        time.sleep(0.5)

    print()
    time.sleep(1)

    # ── Fase 2: Ráfaga de subdominios aleatorios (ataque Kaminsky) ───────────
    print(f"{RED}[FASE 2] Iniciando ráfaga de subdominios inexistentes...{RESET}")
    print(f"         Objetivo: {DNS_RESOLVER_IP} | Dominio: {DOMINIO_BASE}\n")

    N_QUERIES = 20        # número de subdominios falsos
    DELAY     = 0.1       # segundos entre queries (ráfaga rápida)

    for i in range(N_QUERIES):
        sub = random_subdomain(random.randint(8, 14))
        fqdn = f"{sub}.{DOMINIO_BASE}"
        dns_query(fqdn, DNS_RESOLVER_IP)
        time.sleep(DELAY)

    print(f"\n{CYAN}[*] Ataque finalizado. Revisar alertas en el detector.{RESET}\n")
