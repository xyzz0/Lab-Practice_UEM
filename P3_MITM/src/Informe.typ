// ─────────────────────────────────────────────────────────────────────────────
//  PRÁCTICA 3 — MITM Y SUPLANTACIÓN
//  Técnicas de Hacking · Universidad Europea
//  Informe técnico
// ─────────────────────────────────────────────────────────────────────────────

// ── Fuentes y configuración global ───────────────────────────────────────────
#set page(
  paper: "a4",
  margin: (top: 2.5cm, bottom: 2.5cm, left: 2.8cm, right: 2.5cm),
  header: context {
    if counter(page).get().first() > 1 {
      set text(size: 8pt, fill: luma(130))
      grid(
        columns: (1fr, 1fr),
        align(left)[Técnicas de Hacking — Práctica 3],
        align(right)[MITM y Suplantación],
      )
      line(length: 100%, stroke: 0.4pt + luma(180))
    }
  },
  footer: context {
    if counter(page).get().first() > 1 {
      set text(size: 8pt, fill: luma(130))
      line(length: 100%, stroke: 0.4pt + luma(180))
      align(center)[
        #counter(page).display("1 / 1", both: true)
      ]
    }
  },
)

#set text(font: "New Computer Modern", size: 11pt, lang: "es")
#set par(justify: true, leading: 0.75em)
#set heading(numbering: "1.1.")

// ── Estilos de bloques de código ──────────────────────────────────────────────
#show raw.where(block: true): it => block(
  fill: luma(245),
  inset: (x: 12pt, y: 10pt),
  radius: 4pt,
  stroke: 0.5pt + luma(200),
  width: 100%,
  text(size: 8.5pt, font: "New Computer Modern Mono", it),
)

#show raw.where(block: false): it => box(
  fill: luma(245),
  inset: (x: 3pt, y: 1pt),
  radius: 2pt,
  text(size: 9pt, font: "New Computer Modern Mono", it),
)

// ── Cajas de alerta / info ────────────────────────────────────────────────────
#let alerta(cuerpo) = block(
  fill: rgb("#fff3cd"),
  inset: 10pt,
  radius: 4pt,
  stroke: 0.6pt + rgb("#ffc107"),
  width: 100%,
  cuerpo,
)

#let info(cuerpo) = block(
  fill: rgb("#e8f4fd"),
  inset: 10pt,
  radius: 4pt,
  stroke: 0.6pt + rgb("#3498db"),
  width: 100%,
  cuerpo,
)

#let firma(numero, titulo, cuerpo) = block(
  fill: rgb("#fdf2f8"),
  inset: 10pt,
  radius: 4pt,
  stroke: 0.6pt + rgb("#8e44ad"),
  width: 100%,
  [*Firma #numero — #titulo* \ #cuerpo],
)

// ── Placeholder de imagen ─────────────────────────────────────────────────────
#let img(etiqueta) = block(
  fill: luma(235),
  inset: 20pt,
  radius: 4pt,
  stroke: 1pt + luma(180),
  width: 100%,
  align(center, text(fill: luma(100), style: "italic")[📷 #etiqueta]),
)

// ─────────────────────────────────────────────────────────────────────────────
//  PORTADA
// ─────────────────────────────────────────────────────────────────────────────
#page(
  margin: (top: 3cm, bottom: 3cm, left: 3cm, right: 3cm),
  header: none,
  footer: none,
)[
  #align(center)[
    #text(size: 13pt, weight: "bold", tracking: 3pt)[TÉCNICAS DE HACKING]
    #v(0.4cm)
    #line(length: 80%, stroke: 1pt)
    #v(0.6cm)
    #text(size: 22pt, weight: "bold")[Práctica 3]
    #v(0.2cm)
    #text(size: 18pt)[MITM y Suplantación]
    #v(0.6cm)
    #line(length: 80%, stroke: 1pt)
    #v(1.5cm)

    #text(size: 11pt)[
      *Detección de ARP Spoofing y DNS Snooping* \
      mediante sistemas IDS basados en firmas con Scapy
    ]

    #v(3cm)

    #grid(
      columns: (1fr, 1fr),
      gutter: 1cm,
      align(left)[
        *Asignatura* \
        Técnicas de Hacking

        #v(0.3cm)
        *Grado* \
        Ingeniería Informática en Ciberseguridad

        #v(0.3cm)
        *Alumno* \
        Arturo Fernández Merino
      ],
      align(left)[
        *Profesor* \
        Alfredo Robledano 

        #v(0.3cm)
        *Fecha de entrega* \
        Mayo 2026

        #v(0.3cm)
        *Entorno* \
        Kali Linux (VM) + Docker
      ],
    )

    #v(3cm)

  ]
]

// ─────────────────────────────────────────────────────────────────────────────
//  ÍNDICE
// ─────────────────────────────────────────────────────────────────────────────
#outline(
  title: [Índice de contenidos],
  indent: 1.5em,
  depth: 3,
)

#pagebreak()

// ─────────────────────────────────────────────────────────────────────────────
//  RESUMEN EJECUTIVO
// ─────────────────────────────────────────────────────────────────────────────
= Resumen ejecutivo

El presente informe documenta el diseño, implementación y validación de un sistema
de detección de intrusiones (IDS) basado en firmas para dos vectores de ataque de red:
el *envenenamiento de tablas ARP* (ARP Spoofing) y el *reconocimiento y suplantación
mediante DNS* (ataque de Kaminsky / DNS Snooping).

Ambos sistemas han sido validados en entornos virtualizados con Docker, ejecutando
los ataques desde la propia máquina Kali Linux anfitriona y detectándolos mediante
scripts Python desarrollados con la librería Scapy.

#v(0.3cm)

#grid(
  columns: (1fr, 1fr),
  gutter: 0.8cm,
  info[
    *Parte 1 — ARP Spoofing* \
    - 3 firmas de detección implementadas
    - Ataque bidireccional MITM validado
    - Alertas en tiempo real verificadas
  ],
  info[
    *Parte 2 — DNS Snooping* \
    - 3 firmas de detección implementadas
    - Simulación de ataque Kaminsky validada
    - Umbral de NXDOMAINs verificado
  ],
)

#pagebreak()

// ─────────────────────────────────────────────────────────────────────────────
//  PARTE 1 — ARP SPOOFING
// ─────────────────────────────────────────────────────────────────────────────
= Detección de envenenamiento ARP

== Fundamentos teóricos

El protocolo ARP (_Address Resolution Protocol_) opera en la capa 2 del modelo OSI
y permite asociar direcciones IP con direcciones MAC dentro de un mismo segmento de
red. Su diseño carece de mecanismos de autenticación: cualquier nodo puede enviar
una respuesta ARP (_reply_) afirmando poseer cualquier dirección IP, y los receptores
actualizarán su caché sin verificación alguna.

El *ARP Spoofing* (también denominado ARP Poisoning) explota esta debilidad enviando
respuestas ARP falsas de forma continua. El objetivo habitual es un ataque
*Man-In-The-Middle* (MITM): el atacante convence simultáneamente a la víctima de
que él es el router, y al router de que él es la víctima. A partir de ese momento,
todo el tráfico entre ambos pasa por el atacante, quien puede interceptarlo,
modificarlo o simplemente registrarlo.

== Topología del escenario

El escenario se ha desplegado mediante Docker Compose con dos redes bridge:

```
Kali Linux (atacante/monitor)
MAC: 02:42:55:d5:c8:7f  —  br-5abcc0f65712 (10.99.1.254)
          │
          │  lan_interna  10.99.1.0/24
    ┌─────┴──────┐
    │            │
┌───┴────┐  ┌───┴────┐          lan_externa 10.99.2.0/24
│victima │  │ router │ ──────────────────────────────────┐
│10.99.1 │  │10.99.1 │10.99.2.1                          │
│  .10   │  │  .1    │                            ┌──────┴──────┐
└────────┘  └────────┘                            │servidor_web │
                                                  │ 10.99.2.20  │
                                                  └─────────────┘
```

#figure(
  image("DC.png", width: 100%),
  caption: [ Contenedores],
) 
=== Justificación técnica de la topología

La separación en dos redes bridge es necesaria por dos razones:

+ *Condición L2 para ARP:* El envenenamiento ARP solo es efectivo entre nodos
  que comparten el mismo dominio de broadcast (capa 2). Víctima, router y
  atacante deben estar en la misma red bridge (`lan_interna`).

+ *Realismo del escenario MITM:* El servidor web se sitúa en una red externa
  (`lan_externa`) a la que la víctima solo puede llegar a través del router.
  Así, interceptar el tráfico víctima→router tiene consecuencias reales
  (la víctima no puede llegar al servidor web sin pasar por el atacante).

El atacante/monitor es la propia máquina Kali Linux, conectada a la bridge
`br-5abcc0f65712` que Docker crea para `lan_interna`. Esto es posible porque
Docker en Linux expone las redes bridge directamente como interfaces del host.

== Herramienta de ataque: bettercap y Scapy

=== bettercap

Se intentó inicialmente el envenenamiento con bettercap:

```bash
sudo bettercap -iface br-5abcc0f65712 -eval \
  "set arp.spoof.targets 10.99.1.10,10.99.1.1; net.probe on; arp.spoof on"
```

bettercap detectó correctamente los endpoints pero emitió repetidamente el
aviso `could not find spoof targets`. Esto se debe a que los contenedores
Docker responden al ARP probe con latencias variables, provocando que bettercap
marque los endpoints como `lost` antes de poder enviar los replies falsos.

=== Script Scapy (`ataque_arp.py`)

Se desarrolló un script propio en Scapy que implementa el mismo ataque de
forma más robusta, enviando los ARP replies directamente sin depender de un
ciclo de descubrimiento previo:

```python
def envenenar(ip_victima, mac_victima, ip_suplantar, intervalo=1.5):
    pkt = (
        Ether(dst=mac_victima) /
        ARP(
            op=2,                # is-at (reply)
            pdst=ip_victima,     # destinatario del engaño
            hwdst=mac_victima,   # MAC del destinatario
            psrc=ip_suplantar,   # IP que suplantamos
            hwsrc=MAC_ATACANTE   # nuestra MAC
        )
    )
    while True:
        sendp(pkt, iface=IFACE, verbose=False)
        time.sleep(intervalo)
```

El ataque se lanza en dos hilos simultáneos:
- *Hilo 1:* dice a la víctima (`10.99.1.10`) que el router (`10.99.1.1`) tiene
  la MAC del atacante.
- *Hilo 2:* dice al router (`10.99.1.1`) que la víctima (`10.99.1.10`) tiene
  la MAC del atacante.

#img("Screenshot: salida de ataque_arp.py mostrando los dos hilos activos")

== Sistema de detección: `alert_arpspoof`

La función `alert_arpspoof` se registra como callback en `scapy.sniff()` y
analiza cada paquete ARP capturado aplicando tres firmas de detección:

#firma(1, "MAC-IP incongruente")[
  *Campo analizado:* `psrc` (IP origen) y `hwsrc` (MAC origen) del ARP reply. \
  *Condición:* La misma IP responde con una MAC diferente a la registrada en
  la tabla interna del IDS. \
  *Fundamento:* En condiciones normales, la asociación IP↔MAC de un nodo no
  cambia. Un cambio brusco indica que otro nodo está reclamando esa IP.
]

#firma(2, "Gratuitous ARP sospechoso")[
  *Campo analizado:* `psrc == pdst` en un ARP reply (`op=2`). \
  *Condición:* El paquete tiene como IP origen e IP destino la misma dirección. \
  *Fundamento:* El Gratuitous ARP legítimo lo emiten los nodos al arrancar para
  anunciar su presencia. En medio de una sesión activa, es una señal de
  envenenamiento masivo de caché.
]

#firma(3, "ARP reply no solicitado")[
  *Campo analizado:* Correlación temporal entre `op=1` (request) y `op=2` (reply). \
  *Condición:* Llega un ARP reply para una IP por la que no se registró ningún
  request en los últimos 5 segundos. \
  *Fundamento:* El protocolo ARP es request-response. Un reply sin request
  previo es una anomalía inequívoca.
]

=== Implementación del sniff

```python
sniff(
    filter="arp",
    prn=alert_arpspoof,
    store=False,
    iface="br-5abcc0f65712"   # interfaz bridge de lan_interna
)
```

La especificación explícita de `iface` es crítica: sin ella, Scapy en Linux
escucha por defecto en la primera interfaz disponible (`eth0`), que pertenece
a la red del hipervisor y no al segmento Docker donde circula el tráfico ARP.

== Evidencias de la detección

#figure(
  image("EvidenciaSpoofing.png", width: 100%),
  caption: [ Evidencia],
) 


#pagebreak()

// ─────────────────────────────────────────────────────────────────────────────
//  PARTE 2 — DNS SNOOPING
// ─────────────────────────────────────────────────────────────────────────────
= Suplantación y anomalías DNS

== Fundamentos teóricos

=== El ataque de Kaminsky (2008)

Dan Kaminsky descubrió en 2008 una vulnerabilidad crítica en el mecanismo de
resolución iterativa DNS. El ataque se basa en envenenar la caché de un resolver
recursivo aprovechando la debilidad del Transaction ID de 16 bits:

+ El atacante inunda el resolver con consultas a *subdominios inexistentes*
  de un dominio objetivo (`rand1234.banco.com`, `xkz91.banco.com`...).
+ Para cada consulta, el resolver contacta al servidor NS autoritativo, abriendo
  una ventana de tiempo durante la cual espera la respuesta.
+ El atacante bombardea simultáneamente el resolver con respuestas DNS *forjadas*
  que incluyen un registro adicional (`Additional Records`) envenenado para el
  dominio raíz (`banco.com → IP_atacante`).
+ Si el atacante adivina el Transaction ID de 16 bits y el puerto UDP fuente
  antes de que llegue la respuesta legítima, *envenena la caché*.

La clave del ataque es usar subdominios inexistentes: cada NXDOMAIN fuerza
una nueva consulta externa y, por tanto, una nueva ventana de ataque.

=== DNS Snooping

El DNS Snooping es la variante pasiva: al consultar subdominios inexistentes
de una organización, el atacante obtiene información sobre su infraestructura
interna — qué subdominios existen (NOERROR) y cuáles no (NXDOMAIN) — sin
necesidad de acceso directo a la red interna.

== Topología del escenario

```
dns_net — 172.20.0.0/24
┌─────────────────┐
│   dns_server    │ 172.20.0.10   BIND9 — zona autoritativa practica.local
└────────┬────────┘
         │
┌────────┴────────┐
│  dns_resolver   │ 172.20.0.20   IDS: detector_dns.py (escucha udp/53)
└────────┬────────┘
         │
┌────────┴────────┐
│  atacante_dns   │ 172.20.0.99   generador_dns.py (simula Kaminsky)
└─────────────────┘
```

#figure(
  image("DC2.png", width: 100%),
  caption: [Contenedores],
)

=== Configuración del servidor DNS (BIND9)

Se ha configurado una zona autoritativa `practica.local` con registros reales:

```dns
$TTL 60
@   IN  SOA dns_server. admin.practica.local. ( 2026050401 ... )
@   IN  NS  dns_server.

www   IN  A  172.20.0.50
mail  IN  A  172.20.0.51
vpn   IN  A  172.20.0.52
```

Los subdominios `www`, `mail` y `vpn` existen (responden NOERROR).
Cualquier otro subdominio consultado devolverá NXDOMAIN.

== Sistema de detección: `alert_dnssnooping`

#firma(1, "Threshold de volumen de queries")[
  *Umbral:* 10 consultas DNS desde la misma IP en una ventana de 5 segundos. \
  *Implementación:* Ventana deslizante con lista de timestamps por IP origen. \
  *Fundamento:* El tráfico DNS legítimo es disperso. Una ráfaga concentrada
  de una misma fuente indica reconocimiento automatizado.
]

#firma(2, "Ráfaga de respuestas NXDOMAIN")[
  *Umbral:* 5 respuestas NXDOMAIN desde la misma IP en 5 segundos. \
  *Implementación:* Correlación de queries (op=request) con sus respuestas
  (op=response, rcode=3) mediante el Transaction ID. \
  *Fundamento:* Es la firma característica del ataque de Kaminsky: el atacante
  necesita consultar subdominios inexistentes para forzar consultas externas
  y abrir ventanas de envenenamiento.
]

#firma(3, "Prefijo aleatorio (patrón Kaminsky)")[
  *Método:* Heurística de entropía sobre el label más a la izquierda del FQDN. \
  *Condición:* Ratio de vocales < 15% o ratio de dígitos > 40%. \
  *Fundamento:* Los subdominios generados algorítmicamente tienen distribución
  de caracteres muy diferente a los nombres humanos (`xzkvbtrmpl`, `mn4q7rs91`).
]

=== Implementación del detector

```python
def alert_dnssnooping(pkt):
    # Procesamos queries (qr=0)
    if dns.qr == 0:
        queries_por_ip[ip_src].append(ahora)
        # Firma 1: volumen
        if len(queries_por_ip[ip_src]) >= UMBRAL_QUERIES:
            print(f"ALERTA — Firma 1: UMBRAL DE QUERIES SUPERADO")
        # Firma 3: prefijo aleatorio
        if parece_aleatorio(subdominio):
            print(f"ALERTA — Firma 3: PREFIJO ALEATORIO (Kaminsky)")

    # Procesamos respuestas (qr=1)
    elif dns.qr == 1 and rcode == 3:  # NXDOMAIN
        nxdomain_por_ip[ip_src].append((ahora, qname))
        # Firma 2: ráfaga NXDOMAINs
        if len(nxdomain_por_ip[ip_src]) >= UMBRAL_NXDOMAIN:
            print(f"ALERTA — Firma 2: RÁFAGA DE NXDOMAIN")
```

== Script generador: simulación del ataque Kaminsky

El script `generador_dns.py` ejecuta el ataque en dos fases bien diferenciadas:

=== Fase 1 — Tráfico legítimo (línea base)

```python
legitimas = ["www.practica.local", "mail.practica.local",
             "vpn.practica.local", "google.com", "github.com"]
for dominio in legitimas:
    dns_query(dominio, DNS_RESOLVER_IP)
    time.sleep(0.5)
```

Esta fase no debe disparar ninguna alerta. Sirve para demostrar que el IDS
no genera falsos positivos con tráfico normal.

=== Fase 2 — Ráfaga Kaminsky

```python
for i in range(20):
    sub = random_subdomain(random.randint(8, 14))  # ej: "xzkvbtrmpl"
    fqdn = f"{sub}.practica.local"
    dns_query(fqdn, DNS_RESOLVER_IP)
    time.sleep(0.1)   # ráfaga rápida: 10 queries/segundo
```

Genera 20 consultas a subdominios aleatorios en ~2 segundos, lo que supera
todos los umbrales del IDS.

== Evidencias de la detección

#figure(
  image("Snooping1.png", width: 100%),
  caption: [Evidencia],
)

#figure(
  image("Snooping2.png", width: 100%),
  caption: [Ataque],
)


Salida esperada del IDS durante la Fase 2:

```
[14:45:01] NXDOMAIN  #1 | 172.20.0.99 → xzkvbtrmpl.practica.local
[14:45:01] NXDOMAIN  #2 | 172.20.0.99 → mnpqrs4571.practica.local
[14:45:01] ⚠  ALERTA — Firma 3: PREFIJO ALEATORIO (Kaminsky)
  IP origen    : 172.20.0.99
  Subdominio   : xzkvbtrmpl  ← parece generado aleatoriamente

[14:45:02] ⚠  ALERTA — Firma 2: RÁFAGA DE NXDOMAIN
  IP origen   : 172.20.0.99
  NXDOMAINs   : 5 en los últimos 5s
  Posible DNS Snooping / ataque de Kaminsky

[14:45:02] ⚠  ALERTA — Firma 1: UMBRAL DE QUERIES SUPERADO
  IP origen : 172.20.0.99
  Queries   : 10 en los últimos 5s
```

#pagebreak()

// ─────────────────────────────────────────────────────────────────────────────
//  ANÁLISIS Y CONCLUSIONES
// ─────────────────────────────────────────────────────────────────────────────
= Análisis y conclusiones

== Efectividad del sistema IDS

Ambos detectores han demostrado ser capaces de identificar los ataques en tiempo
real con una latencia inferior a 2 segundos desde el inicio del ataque. La
arquitectura de ventana deslizante implementada en el detector DNS permite
ajustar los umbrales para equilibrar sensibilidad y tasa de falsos positivos.

=== Limitaciones identificadas

- *ARP:* El detector requiere especificar explícitamente la interfaz bridge.
  En un despliegue real se necesitaría un mecanismo de autodescubrimiento.
- *DNS:* El umbral de 10 queries/5s podría generar falsos positivos en entornos
  con resolución DNS muy activa (CDNs, aplicaciones SPA).
- *Evasión:* Un atacante sofisticado podría evadir la Firma 3 del ARP usando
  intervalos largos entre replies, o evadir la Firma DNS usando múltiples IPs
  origen.

== Mitigaciones recomendadas

#grid(
  columns: (1fr, 1fr),
  gutter: 0.8cm,
  block[
    *Contra ARP Spoofing:*
    - _Dynamic ARP Inspection_ (DAI) en switches gestionados
    - Entradas ARP estáticas para nodos críticos
    - Segmentación con VLANs
    - 802.1X para autenticación de puerto
  ],
  block[
    *Contra Kaminsky / DNS Snooping:*
    - DNSSEC para validación criptográfica
    - Randomización de puerto UDP fuente (RFC 5452)
    - DNS sobre TLS (DoT) o HTTPS (DoH)
    - Rate limiting en el resolver
  ],
)

== Conclusión

La práctica ha permitido comprender en profundidad los mecanismos de dos ataques
clásicos de red — ARP Spoofing y DNS Kaminsky — y diseñar contramedidas de
detección basadas en el análisis de anomalías en el tráfico de red. La
implementación con Scapy demuestra la viabilidad de construir sistemas IDS
ligeros y específicos sin necesidad de herramientas comerciales.

#pagebreak()

// ─────────────────────────────────────────────────────────────────────────────
//  REFERENCIAS
// ─────────────────────────────────────────────────────────────────────────────
= Referencias

#set par(justify: false)

+ Plummer, D. C. (1982). _An Ethernet Address Resolution Protocol_. RFC 826. IETF.

+ Kaminsky, D. (2008). _It's the End of the Cache As We Know It_.
  Black Hat USA 2008. Presentación técnica.

+ Arends, R. et al. (2005). _DNS Security Introduction and Requirements_.
  RFC 4033. IETF.

+ Herzberg, A. & Shulman, H. (2012). _Fragmentation Considered Poisonous_.
  IEEE CNS 2012.

+ Scapy Project. (2024). _Scapy Documentation_. #link("https://scapy.readthedocs.io")

+ bettercap Project. (2024). _bettercap Documentation_. #link("https://www.bettercap.org")

+ ISC BIND9. (2024). _BIND 9 Administrator Reference Manual_.
  #link("https://bind9.readthedocs.io")
