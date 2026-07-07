// ── Fuentes y configuración global ───────────────────────────────────────────
#set page(
  paper: "a4",
  margin: (top: 2.5cm, bottom: 2.5cm, left: 2.8cm, right: 2.5cm),
  header: context {
    if counter(page).get().first() > 1 {
      set text(size: 8pt, fill: luma(130))
      grid(
        columns: (1fr, 1fr),
        align(left)[Técnicas de Hacking — Práctica 2],
        align(right)[Reconocimiento Activo],
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
    #text(size: 22pt, weight: "bold")[Práctica 2]
    #v(0.2cm)
    #text(size: 18pt)[Reconocimiento Activo]
    #v(0.6cm)
    #line(length: 80%, stroke: 1pt)


    #v(2cm)

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
#v(0.3cm)
#outline(
  title: [Índice de contenidos],
  indent: 2.5em,
  depth: 3,
)
#pagebreak()

// ─────────────────────────────────────────────────────────────────────────────
= Introducción
// ─────────────────────────────────────────────────────────────────────────────
#v(0.3cm)

El *reconocimiento activo* es la fase de una auditoría en la que el atacante envía
estímulos a la red objetivo y analiza las respuestas para inferir qué dispositivos
están vivos y qué servicios exponen. A diferencia del reconocimiento pasivo, aquí sí
se genera tráfico dirigido al objetivo, por lo que es una técnica más ruidosa pero
también más precisa.

Esta práctica se divide en dos bloques. En el primero se implementa una herramienta
propia de _host discovery_ en Python con la librería Scapy, apoyada en tres estímulos
independientes —UDP, TCP (ACK) e ICMP (timestamp)— y se utiliza para detectar hosts
activos. En el segundo se analiza, mediante un _packet sniffer_, el comportamiento
por defecto de nmap en el reconocimiento de puertos y su estado.

#info[
  Todo el trabajo se realiza sobre un entorno virtualizado y contenerizado, conforme
  a las restricciones de la práctica: una máquina *Kali Linux* como atacante y un
  laboratorio de contenedores *Docker* que hace las veces de red objetivo.
]

#pagebreak()

// ─────────────────────────────────────────────────────────────────────────────
= Desarrollo
// ─────────────────────────────────────────────────────────────────────────────
#v(0.3cm)

== Descubrimiento de hosts con Scapy

=== La función `craft_discovery_pkts`

La función construye y devuelve una *lista de paquetes* lista para enviar con `sr()`,
separando deliberadamente el _crafteo_ del _envío_. De este modo la misma función
puede reutilizarse en distintos scripts (envío síncrono con `sr`, asíncrono, por
lotes, etc.) sin acoplarla a una forma concreta de transmisión.

Sus argumentos son:

- `protocolos` (*obligatorio*): admite un `str` o una lista de `str`. Internamente se
  normaliza a una lista en mayúsculas y se valida contra el conjunto
  `{UDP, TCP, ICMP}`, lanzando `ValueError` ante cualquier protocolo no soportado.
- `objetivos` (*obligatorio*): una IP única o un rango en formato Scapy
  (p.ej. `"172.28.0.0/24"`). Se pasa tal cual a `IP(dst=...)`; Scapy expande el rango
  de forma perezosa en el momento del envío.
- `num_pkts` (*opcional*): diccionario `{protocolo: nº de paquetes}`. Si no se pasa,
  se craftea un único paquete de cada tipo exigido; si el diccionario existe pero le
  falta una clave concreta, se asume 1 para ese protocolo.
- `puerto` (*opcional*): puerto de capa 4 (L4) para TCP y UDP; por defecto, el 80.

Cada estímulo se apoya en un comportamiento distinto de la pila para revelar un host
vivo:

- *ICMP timestamp* (`type=13`): un host que lo soporta responde con un _timestamp
  reply_ (`type=14`).
- *TCP ACK* (`flags="A"`): al no existir una conexión previa establecida, el host
  responde con un `RST`.
- *UDP* a un puerto cerrado: el host responde con un `ICMP port-unreachable`
  (type 3, code 3).

En los tres casos, cualquier respuesta delata la IP del emisor en el campo
`respuesta.src`, que es justo lo que recolecta la función auxiliar `hosts_activos`.


=== Entorno de pruebas

El laboratorio se define con Docker Compose sobre una red _bridge_ aislada
(`172.28.0.0/24`). Se despliegan dos hosts activos y se deja una IP libre a propósito
para disponer del caso de "host inactivo" que exige el enunciado. El objetivo
multi-servicio (`lab-target`) es una imagen mínima de Alpine que levanta `sshd` y
`nginx`, exponiendo por tanto dos puertos abiertos (22 y 80) para la segunda parte.

#figure(
  table(
    columns: (auto, auto, auto, 1fr),
    stroke: 0.5pt + luma(200),
    inset: 7pt,
    align: (left, left, center, left),
    table.header([*Host*], [*IP*], [*Estado*], [*Servicios*]),
    [`lab-target`], [`172.28.0.10`], [activo], [SSH (22), HTTP (80)],
    [`lab-web`], [`172.28.0.20`], [activo], [HTTP (80)],
    [(libre)], [`172.28.0.99`], [inactivo], [— (caso de host muerto)],
  ),
  caption: [Topología del laboratorio de contenedores.],
)

== Comportamiento por defecto de nmap y estado de puertos

=== Estado de un puerto

El *estado de un puerto* es la conclusión a la que llega el escáner tras enviar un
estímulo y observar (o no) la respuesta. Depende de si hay un servicio escuchando y
de si existe filtrado por el camino. Para un _SYN scan_ los estados relevantes son:

#figure(
  table(
    columns: (auto, 1.3fr, 1.5fr),
    stroke: 0.5pt + luma(200),
    inset: 7pt,
    align: (left, left, left),
    table.header([*Estado*], [*Significado*], [*Estímulo → Respuesta*]),
    [Abierto],
    [Hay un servicio escuchando y aceptando conexiones.],
    [`SYN → SYN/ACK`; nmap responde `RST` y no completa el _handshake_.],
    [Cerrado],
    [El host está vivo pero ningún servicio escucha en ese puerto.],
    [`SYN → RST/ACK`.],
    [Filtrado],
    [Un cortafuegos descarta el estímulo; nmap no puede decidir.],
    [`SYN → (sin respuesta)` o `ICMP unreachable` (type 3).],
  ),
  caption: [Estados de un puerto y patrón estímulo/respuesta en un SYN scan.],
)

=== Comportamiento por defecto de nmap

Ejecutado como root, el escaneo por defecto de nmap es un *SYN scan* (`-sS`), también
llamado _half-open_ porque no completa el 3-way handshake. Sin privilegios, recurre a
un *connect scan* (`-sT`), que sí abre la conexión completa mediante la llamada
`connect()`. Por defecto nmap no barre los 65535 puertos, sino los *1000 puertos más
comunes* según su base de datos `nmap-services`, con una temporización `-T3` y
retransmisiones cuando un puerto no responde.

#alerta[
  Nmap, por defecto, realiza además descubrimiento de hosts (_ping_) y resolución DNS.
  Como esta parte se centra únicamente en el reconocimiento de puertos, ese tráfico se
  descarta lanzando el escaneo con `-Pn` (omitir descubrimiento) y `-n` (omitir DNS).
]

#pagebreak()

// ─────────────────────────────────────────────────────────────────────────────
= Resultados
// ─────────────────────────────────────────────────────────────────────────────
#v(0.3cm)

== Host discovery con Scapy

Tras levantar el laboratorio, se lanza `host_discovery.py` contra un host activo
(`172.28.0.10`) y contra la IP libre (`172.28.0.99`), capturando el tráfico con
`tcpdump` en la interfaz del _bridge_. La salida del script identifica correctamente
los hosts vivos y descarta la IP sin host.

#figure(
  image("images/Deteccion.png", width: 80%),
  caption: [Salida del script: se detectan como activos los hosts que responden,
    mientras que la IP `172.28.0.99` no genera respuesta alguna.],
) <fig-deteccion>

La captura completa en Wireshark muestra el conjunto de estímulos enviados y las
respuestas recibidas, que analizamos a continuación estímulo por estímulo.

#figure(
  image("images/WireShark.png", width: 100%),
  caption: [Vista general de la captura del _host discovery_ en Wireshark.],
) <fig-wireshark>

#firma("1", "ICMP timestamp")[
  Estímulo `ICMP type=13` (_timestamp request_). Un host vivo responde con
  `ICMP type=14` (_timestamp reply_); la presencia del reply confirma el host activo.
]

#figure(
  image("images/FiltroICMP.png", width: 100%),
  caption: [Filtro `icmp.type==13 or icmp.type==14`: petición y respuesta de
    timestamp.],
) <fig-icmp>

#firma("2", "TCP ACK")[
  Estímulo `TCP` con `flags="A"` (ACK) al puerto 80. Al no existir conexión previa,
  el host vivo responde con un `RST`, lo que delata su presencia.
]

#figure(
  image("images/FiltroTCP.png", width: 100%),
  caption: [Filtro `tcp.flags.ack==1 and tcp.flags.syn==0`: ACK enviado y `RST` de
    respuesta.],
) <fig-tcp>

#firma("3", "UDP")[
  Estímulo `UDP` a un puerto cerrado. El host vivo responde con un
  `ICMP port-unreachable` (type 3, code 3), indicando que la máquina está activa
  aunque el puerto no ofrezca servicio.
]

#figure(
  image("images/FiltroUDP.png", width: 100%),
  caption: [Filtro `udp.port==80 or icmp.type==3`: datagrama UDP y su
    _port-unreachable_.],
) <fig-udp>

== Escaneo de puertos con nmap

Se lanza el escaneo por defecto descartando descubrimiento y DNS
(`nmap -Pn -n 172.28.0.10`) para observar únicamente el reconocimiento de puertos.
Nmap identifica los dos servicios expuestos por el objetivo.

#figure(
  image("images/Nmap.png", width: 90%),
  caption: [Salida de nmap: puertos 22 (SSH) y 80 (HTTP) abiertos en el objetivo.],
) <fig-nmap>

En la captura se comprueba el *conteo de puertos*: nmap envía un segmento SYN a cada
uno de los 1000 puertos más comunes —comportamiento por defecto—, en lugar de barrer
el espacio completo de 65535 puertos. En cuanto al *conteo de paquetes*, se aprecian
retransmisiones de SYN hacia los puertos que no responden.

#firma("4", "Puerto abierto")[
  Patrón `SYN → SYN/ACK → RST`. Ante un puerto con servicio (22 y 80), el objetivo
  responde `SYN/ACK`; nmap contesta con `RST` para no completar el handshake
  (característico del _half-open_ SYN scan).
]

#figure(
  image("images/Nmap80TCP.png", width: 100%),
  caption: [Reconocimiento del puerto 80: estímulo `SYN` y respuesta `SYN/ACK`
    (puerto abierto).],
) <fig-nmap80-1>

#figure(
  image("images/Nmap80TCP2.png", width: 100%),
  caption: [Detalle del intercambio sobre el puerto 80 durante el escaneo.],
) <fig-nmap80-2>

#firma("5", "Puerto cerrado")[
  Patrón `SYN → RST/ACK`. Ante un puerto sin servicio, el host —que está vivo—
  responde directamente con `RST`, permitiendo a nmap clasificarlo como _closed_.
]

#figure(
  image("images/NmapRST.png", width: 100%),
  caption: [Respuesta `RST` del objetivo ante el sondeo de un puerto cerrado.],
) <fig-rst>

#pagebreak()

// ─────────────────────────────────────────────────────────────────────────────
= Conclusión
// ─────────────────────────────────────────────────────────────────────────────
#v(0.3cm)

Se ha implementado una herramienta de _host discovery_ funcional y modular que,
mediante tres estímulos independientes (ICMP timestamp, TCP ACK y UDP), distingue
correctamente los hosts activos de las IPs sin host. Las capturas evidencian, en cada
caso, el par estímulo/respuesta esperado: _timestamp reply_ para ICMP, `RST` para el
ACK y _port-unreachable_ para UDP.

En la segunda parte se ha caracterizado el comportamiento por defecto de nmap: un SYN
scan _half-open_ sobre los 1000 puertos más comunes, con el patrón
`SYN → SYN/ACK → RST` para los puertos abiertos y `SYN → RST` para los cerrados. El
uso de `-Pn -n` ha permitido aislar el tráfico de reconocimiento de puertos del de
descubrimiento de hosts, tal y como pedía el enunciado. El conjunto valida tanto la
implementación propia como la comprensión del comportamiento de una herramienta
estándar de la industria.

La gran diferencia es la calidad de los escaneos, en uno más personalizado generamos una cantidad de ruido bastante menor la cual es adaptada al contexto y al entorno, sin embargo mediante el uso de herramientas como NMAP, el uso general genera una cantidad excesiva de tráfico, ruido y escaneos innecesarios los cuales pueden llegar a ser desconocidos para alguien inexperto y causar complicaciones o problemas.


#v(5em)
= Bibliografía
#v(0.3cm)
#set par(justify: false)

- Nmap Project. *Nmap Reference Guide (Man Page)*. #link("https://nmap.org/book/man.html")[nmap.org/book/man.html]
- Lyon, G. *Nmap Network Scanning* — Port Scanning Techniques. #link("https://nmap.org/book/scan-methods.html")[nmap.org/book/scan-methods.html]
- Biondi, P. y colaboradores. *Scapy Documentation*. #link("https://scapy.readthedocs.io/")[scapy.readthedocs.io]
- Postel, J. (1981). *RFC 792 — Internet Control Message Protocol*. #link("https://www.rfc-editor.org/rfc/rfc792")[rfc-editor.org/rfc/rfc792]
- Eddy, W. (2022). *RFC 9293 — Transmission Control Protocol*. #link("https://www.rfc-editor.org/rfc/rfc9293")[rfc-editor.org/rfc/rfc9293]
