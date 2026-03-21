// --- SETUP INICIAL ---
#show link: underline
#set page(
  paper: "a4",
  margin: (x: 2.5cm, y: 3cm),
  numbering: "1",
  number-align: right,
  header: align(right)[
    #text(size: 9pt, weight: "bold", fill: luma(100))[
      Universidad Europea de Madrid | Práctica de OSINT
    ]
    #line(length: 100%, stroke: 0.5pt + luma(150))
  ],
)

#set text(
  font: ("Roboto", "Arial", "Helvetica", "sans-serif"),
  size: 11pt,
  lang: "es" // Idioma corregido a español
)

#set heading(numbering: "1.1")
#show heading: set block(above: 1.5em, below: 1em)

// --- TÍTULO Y METADATOS ---
#align(center)[
  #text(size: 22pt, weight: "bold")[OSINT - Técnicas de Hacking]
  #v(1em)
  
  // Bloque sombreado para los datos del reporte
  #block(
    fill: luma(245),
    inset: 16pt,
    radius: 4pt,
    width: 85%,
    align(left)[
      #grid(
        columns: (auto, 1fr),
        gutter: 1.2em,
        [*Empresa Auditada:*], [Telefónica],
        [*Fecha:*], [21/03/2026],
        [*Autor:*], [Arturo Fernández],
        [*Objetivo:*], [Recopilación de información pública y análisis de negocio]
      )
    ]
  )
]
#v(2.5em)
#pagebreak()
#outline(title: "Índice")
#pagebreak()

= Resumen
Este informe presenta un análisis de la presencia digital pública de Telefónica, una de las principales empresas de telecomunicaciones a nivel mundial. Utilizando metodologías de recopilación de información de fuentes abiertas (conocidas como OSINT), se ha cartografiado la infraestructura tecnológica de la compañía desde la perspectiva de un observador externo. El objetivo principal ha sido evaluar qué datos corporativos, técnicos y de red están disponibles públicamente en Internet sin interactuar de forma directa o intrusiva con los sistemas de la empresa. Los resultados muestran una infraestructura altamente madura y segura.

= Introducción
La Inteligencia de Fuentes Abiertas (OSINT) y las técnicas de reconocimiento pasivo constituyen la primera fase crítica en cualquier auditoría de ciberseguridad ética. Estas metodologías permiten a los analistas perfilar y mapear la superficie de ataque de una organización utilizando exclusivamente datos de acceso público, sin emitir ningún paquete o realizar peticiones directas que puedan alertar a la infraestructura del objetivo.

El presente documento tiene como finalidad aplicar estas técnicas teóricas y prácticas sobre un entorno real de máxima exigencia: la multinacional española Telefónica, entidad perteneciente al índice IBEX 35 @robledano2026. 

La investigación se estructura en dos ejes fundamentales:
1. Una fundamentación teórica sobre la relevancia de los registros DNS en las etapas tempranas de perfilado de redes y su relación con el reconocimiento pasivo.
2. Una auditoría práctica ("Information Gathering") que evalúa diversos vectores de exposición, incluyendo el análisis de infraestructura, servicios en la nube, fugas de información a través de motores de búsqueda avanzados (Google Dorking) y la huella digital de la organización en redes sociales.

= Registros DNS
Los registros *DNS* (Domain Name System) proveen información crucial sobre la infraestructura de un dominio. Cada tipo de registro cumple un propósito único:


#grid(
  columns: (5em, 1fr),
  row-gutter: 1.3em,
  
  [*A*], [Mapea un nombre de dominio a una dirección IPv4.],
  [*AAAA*], [Mapea un nombre de dominio a una dirección IPv6.],
  [*MX*], [Especifica los servidores de correo encargados de aceptar emails en nombre del dominio.],
  [*TXT*], [Contiene texto legible por humanos o datos estructurados. Es usado comúnmente en configuraciones de seguridad como *SPF*, *DKIM* o *DMARC*.],
  [*CNAME*], [Crea un alias de un nombre de dominio hacia otro.],
  [*NS*], [Delega una zona DNS para usar un servidor de nombres autoritativo específico.],
  [*SOA*], [Contiene información administrativa importante sobre la zona DNS (Start of Authority).],
  [*PTR*], [Mapea una dirección IP de vuelta a un nombre de dominio (resolución inversa), usado en la verificación anti-spam.]
)

#v(1.5em)
#pagebreak()
#v(1em)

= Auditoría OSINT: Telefónica
A continuación, se detalla la estructura comercial de Telefónica mediante el análisis de fuentes abiertas, dividida en sus clientes, proveedores estratégicos y servicios clave.

== Segmentos de Clientes
Telefónica abarca un mercado amplio, dividiéndose en tres ramas principales:
- *Particulares (B2C):* Usuarios finales y hogares.
- *Empresas y AA.PP. (B2B):* Soluciones integrales para PYMES, multinacionales y sector público.
- *Mayoristas (Wholesale):* Alquiler de su infraestructura física y de red a otros operadores móviles virtuales (OMVs).

== Proveedores Clave
La operatividad global de la compañía depende de una red de socios estratégicos:
- *Infraestructura de red:* Ericsson, Nokia, etc.
- *Fabricantes de dispositivos:* Apple, Samsung, Xiaomi, etc.
- *Contenido y Derechos:* LaLiga, UEFA, productoras cinematográficas.
- *Socios Tecnológicos (Cloud e IT):* Microsoft Azure, Amazon AWS, Google Cloud.

== Catálogo de Servicios
Telefónica ofrece una propuesta de valor que va mucho más allá de las telecomunicaciones tradicionales:
- *Conectividad:* Redes móviles (4G/5G) y banda ancha fija (Fibra Óptica / FTTH).
- *Servicios Digitales (Telefónica Tech):* Ciberseguridad, almacenamiento en la nube, Internet de las Cosas (IoT) y Big Data.
- *Entretenimiento:* Televisión de pago y plataformas de streaming por suscripción.



#pagebreak()

= Investigación de Presencia Digital

== Infraestructura y Dominios (WHOIS)
El análisis inicial de los registros WHOIS @icann_whois sobre el dominio principal revela información clave sobre la gestión de activos de la empresa:

#v(1em)
#grid(
  columns: (9em, 1fr),
  row-gutter: 1.3em,
  
  [*Registrador:*], [Acens Technologies. Al ser una empresa de hosting adquirida por la propia Telefónica, evidencia una estrategia de *integración vertical* para mantener el control de sus dominios críticos.],
  [*Servidores NS:*], [`DNS1.MOVISTAR.ES` y `DNS2.MOVISTAR.ES`],
  [*Estado (Seguridad):*], [El dominio presenta bloqueos de seguridad a nivel de registro (`serverDeleteProhibited`, `serverTransferProhibited` y `serverUpdateProhibited`), mitigando riesgos de secuestro de dominio (Domain Hijacking).]
)

#v(1.5em)

#figure(
  image("WHOIS.png", width: 95%),
  caption: [Captura de evidencia mediante el uso de la herramienta de consola *whois*.],
)
#pagebreak()

== Enumeración DNS y Topología
Mediante el uso de la plataforma de inteligencia #link("https://dnsdumpster.com/")[DNSDumpster] @dnsdumpster, se realizó una recolección pasiva que permitió descubrir la superficie de ataque expuesta de la organización, identificando más de *750 subdominios* asociados a Telefónica.

#figure(
  image("DNSDUMP2.png", width: 90%),
  caption: [Múltiples dominios y subredes obtenidos vía *DNSDumpster*.],
)

#v(1em)
Entre los hallazgos críticos de esta consulta, se identificó el registro *MX* apuntando a `telefonicacorp.mail.protection.outlook.com`. Esto confirma pasivamente que la empresa utiliza la infraestructura en la nube de Microsoft (Office 365) para gestionar su correo corporativo. Adicionalmente, la herramienta generó un mapa topológico de sus servidores:

#v(1.5em)
#figure(
  image("DNSDUMP1.png", width: 95%),
  caption: [Mapa topológico de localizaciones y servidores expuestos vía *DNSDumpster*.],
)

#pagebreak()

== Técnicas de Búsqueda Avanzada (Google Dorking)
El uso de consultas avanzadas ("Dorks") @ghdb en motores de búsqueda permite descubrir información indexada accidentalmente sin interactuar de forma directa con los servidores de la empresa. Se ejecutaron las siguientes pruebas:

#v(1em)

*Dork 1: Filtración de documentos sensibles* \
`site:telefonica.com filetype:xls OR filetype:docx OR filetype:pdf passwords` \
Este comando busca archivos ofimáticos públicos que contengan la palabra clave "passwords". El tercer resultado obtenido apunta a un documento potencialmente clasificado o de uso interno.
#v(1.5em)
#figure(
  image("DORK1.png", width: 90%),
  caption: [Resultados obtenidos por el primer dork (documentos ofimáticos).],
)
#pagebreak()

*Dork 2: Identificación de paneles de acceso* \

`site:telefonica.com AND intitle:"login"` \

Filtra portales de inicio de sesión. Identificar estos paneles es crucial en el perfilado, ya que representan vectores de entrada potenciales para futuros ataques de fuerza bruta o uso de credenciales comprometidas.

#v(1em)
#figure(
  image("DORK2.png", width: 90%),
  caption: [Resultados obtenidos por el segundo dork (paneles de login).],
)
#pagebreak()

*Dork 3: Exposición de bases de datos* \

`filetype:sql OR filetype:sqlitedb OR filetype:db site:telefonica.com` \

Busca volcados de bases de datos expuestos por configuraciones erróneas. En este caso, la búsqueda no arrojó resultados, lo cual es un indicador positivo de las políticas de desindexación y seguridad de la empresa.

#v(1em)
#figure(
  image("DORK3.png", width: 70%),
  caption: [Resultados obtenidos por el tercer dork (sin exposición de BBDD).],
)

== Presencia en Redes Sociales (Perfilado Pasivo)
Telefónica mantiene una presencia activa en diversas plataformas. Para una auditoría OSINT, estas redes son minas de información para preparar vectores de Ingeniería Social:

- #link("https://www.linkedin.com/company/telefonica/")[*LinkedIn:*] Es la red más valiosa para el OSINT corporativo. Permite identificar la jerarquía interna, descubrir el formato estándar de los correos electrónicos (ej. `nombre.apellido@telefonica.com`) y, lo más importante, analizar perfiles técnicos. Las ofertas de trabajo y los currículums de los empleados revelan exactamente qué tecnologías, lenguajes de programación y medidas de seguridad utiliza la empresa internamente.

- #link("https://twitter.com/Telefonica")[*X (Twitter)*] *y GitHub:* Mientras que las cuentas de Twitter (`@Telefonica`, `@movistar_es`) revelan las campañas corporativas y quejas de clientes (útil para suplantación de identidad en Phishing), buscar repositorios públicos de empleados en *GitHub* puede exponer accidentalmente fragmentos de código fuente o claves API en los historiales de *commits*.

#v(1.5em)
#figure(
    image("GITHUB.png", width: 70%),
    caption: [Perfil Github Telefónica]
)

#pagebreak()

== Exposición de Activos y Perfilado de Servicios

Utilizando el motor de búsqueda de dispositivos conectados #link("https://www.shodan.io/")[Shodan] @shodan de forma estrictamente pasiva, se ha procedido a perfilar la huella digital y los servicios expuestos en la infraestructura pública de Telefónica.

El hallazgo más crítico en esta fase ha sido la identificación de múltiples activos corriendo el protocolo *Telnet* (puerto 23), como se detalla en la siguiente evidencia:

#v(1em)
#figure(
  image("SHODAN.png", width: 85%),
  caption: [Resultados de Shodan indexando servicios expuestos y presencia del protocolo inseguro Telnet. Fuente: Elaboración propia/Shodan.],
)
#v(1em)

=== Análisis del Riesgo (Telnet)
La presencia de Telnet expuesto a internet representa un riesgo crítico para la organización debido a las siguientes carencias de seguridad inherentes al protocolo:

1.  *Comunicación en Texto Plano:* A diferencia de SSH, Telnet no cifra el tráfico. Cualquier atacante posicionado en la red (mediante ataques Man-in-the-Middle o Sniffing) puede interceptar y leer las credenciales de administración (usuario y contraseña) sin ningún esfuerzo.
2.  *Vector de Ataque Directo:* Estos paneles de acceso son objetivos prioritarios para ataques de fuerza bruta o "credential stuffing", ya que suelen gestionar dispositivos de red críticos (routers, switches) o sistemas heredados ("legacy") con medidas de seguridad deficientes.
3.  *Impacto Potencial:* El compromiso de estas credenciales podría otorgar a un atacante control total sobre el dispositivo, permitiéndole pivotar hacia la red interna de la compañía o interrumpir servicios críticos.

Este hallazgo subraya la importancia del reconocimiento pasivo para identificar vulnerabilidades graves de configuración antes de que sean explotadas.

#pagebreak()

= Conclusiones
El ejercicio de reconocimiento pasivo llevado a cabo sobre Telefónica demuestra que, incluso en corporaciones del IBEX 35 con infraestructuras altamente fortificadas y altos presupuestos en ciberseguridad, la huella digital siempre expone vectores de información sensibles.

A nivel estratégico y de infraestructura central, Telefónica demuestra una gran madurez de seguridad corporativa. La centralización de sus dominios críticos mediante filiales propias (Acens), la aplicación de bloqueos de seguridad contra secuestros de dominio (Registry Lock) y el uso de proveedores cloud de primer nivel (Microsoft O365) con políticas Anti-Spoofing (SPF) evidencian una arquitectura robusta.

Sin embargo, la inmensidad de su red corporativa (con más de 750 dominios y subdominios indexados) dificulta un control hermético de la superficie de ataque. La fase de enumeración y el uso de Google Dorking han revelado hallazgos de gran valor analítico para un potencial atacante, incluyendo portales de acceso (`login`), metadatos en documentos ofimáticos indexados y, de manera crítica, la exposición de protocolos obsoletos en texto plano (como Telnet) en ciertos activos perimetrales localizados vía Shodan.

En conclusión, el reconocimiento OSINT ha demostrado ser una herramienta metodológica formidable. Permite levantar un mapa altamente detallado de la estructura tecnológica de una multinacional, evidenciando que el control de la exposición pública y la desindexación de activos son tan vitales como la defensa de la red interna.
#v(2em)

#bibliography("bibliografia.bib", title: "Bibliografía", style: "ieee")
