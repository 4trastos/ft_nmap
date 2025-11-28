# ft_nmap

***

# 🔎 Explicación Detallada de Nmap (Network Mapper)

`Nmap` es una utilidad de código abierto, poderosa y flexible, diseñada para el descubrimiento de redes y la auditoría de seguridad. Su función principal es mapear la topología de una red, identificar los *hosts* activos, y determinar qué servicios se están ejecutando y qué sistemas operativos están utilizando.

## 1. Fundamento Técnico: ¿Qué Hace Nmap?

El principio fundamental de Nmap es la **interpretación de las respuestas de la red**. Nmap no se limita a pedir información; envía paquetes de red especialmente diseñados (a veces incompletos o malformados) y analiza cómo responden los sistemas de destino.

El objetivo principal es determinar el **estado de los puertos** de un host:

| Estado del Puerto | Definición |
| :--- | :--- |
| **Open (Abierto)** | Una aplicación está escuchando activamente conexiones o paquetes en ese puerto. Nmap puede interactuar con ella. |
| **Closed (Cerrado)** | No hay una aplicación escuchando, pero el puerto es accesible. El sistema de destino responde con un paquete de reinicio (TCP RST) o con un mensaje ICMP de "destino inalcanzable" (UDP). |
| **Filtered (Filtrado)** | Un cortafuegos (firewall) o un filtro de red impide que Nmap determine si el puerto está abierto o cerrado. Nmap no recibe respuesta o recibe un error ICMP de "comunicación prohibida". |
| **Unfiltered (No filtrado)** | Nmap puede acceder al puerto, pero no puede determinar si está abierto o cerrado (suele ocurrir con escaneos ACK). |

## 2. Funcionalidades Clave de Nmap

Nmap va mucho más allá del simple escaneo de puertos. Sus capacidades se agrupan en cuatro áreas principales:

### A. Descubrimiento de Hosts (Host Discovery)

Antes de escanear puertos, Nmap necesita saber qué máquinas están activas. Utiliza técnicas como peticiones ICMP Echo (*ping*), peticiones ARP (en la red local) o el envío de paquetes TCP/UDP a puertos comunes.

### B. Escaneo de Puertos (Port Scanning)

Es la función central. Nmap utiliza diversos métodos para determinar el estado de miles de puertos en cada *host*.

### C. Detección de Versiones y Servicios (`-sV`)

Si un puerto está abierto, Nmap intenta determinar exactamente qué aplicación lo está utilizando (por ejemplo, Apache, Nginx, o un servidor SSH) y su número de versión preciso. Esto es crucial, ya que las vulnerabilidades a menudo dependen de la versión exacta del software.

### D. Detección de Sistema Operativo (`-O`)

Mediante una técnica llamada **OS Fingerprinting** (toma de huellas dactilares del S.O.), Nmap analiza las particularidades de las respuestas TCP/IP de un host (como el tamaño de la ventana TCP, el valor inicial del TTL, y otros campos de la cabecera) para adivinar con precisión el sistema operativo y la versión que está ejecutando (ej. *Linux Kernel 4.x* o *Windows Server 2019*).

## 3. Los Tipos de Escaneo Más Importantes

La elección del tipo de escaneo determina la velocidad, la precisión y la capacidad de evadir sistemas de detección.

### 1. Escaneo SYN Stealth (`-sS`)

Es el tipo de escaneo más común, rápido y sigiloso.

* **Mecánica:** Nmap envía un paquete **SYN** (el primer paso del *three-way handshake* de TCP) y espera la respuesta.

  * **Puerto Abierto:** Responde con un paquete **SYN-ACK**. Nmap envía un **RST** (Reset) inmediatamente, sin completar la conexión, y marca el puerto como **abierto**.

  * **Puerto Cerrado:** Responde con un paquete **RST**.

* **Ventaja:** Como Nmap nunca completa el *handshake*, muchas aplicaciones no registran la conexión, haciendo que este escaneo sea menos ruidoso.

### 2. Escaneo de Conexión TCP (`-sT`)

Es el escaneo por defecto cuando el usuario no tiene permisos de administrador (no puede usar *raw sockets* para el escaneo SYN).

* **Mecánica:** Nmap utiliza la función `connect()` del sistema operativo, completando el *three-way handshake* TCP (SYN, SYN-ACK, ACK).

* **Desventaja:** Deja un registro completo de conexión en el *host* de destino, lo que lo hace muy ruidoso y fácil de detectar.

### 3. Escaneo UDP (`-sU`)

Los puertos UDP (como DNS o SNMP) son más difíciles de escanear porque UDP no tiene mecanismo de *handshake*.

* **Mecánica:** Nmap envía un paquete UDP vacío o específico al puerto.

  * **Puerto Abierto:** Si recibe una respuesta del servicio o simplemente **no recibe respuesta**, Nmap lo marca como **abierto o filtrado**.

  * **Puerto Cerrado:** El sistema operativo de destino responde con un mensaje ICMP "Puerto inalcanzable".

### 4. Escaneos Evasivos (Null, FIN, Xmas)

Estos escaneos manipulan las banderas de cabecera TCP para intentar pasar desapercibidos ante *firewalls* que solo analizan el paquete SYN. Se basan en la implementación del RFC 793 de TCP.

* **Null Scan (`-sN`):** No se establece ninguna bandera (flags a 0).

* **FIN Scan (`-sF`):** Solo se establece la bandera FIN (Finalizar).

* **Xmas Scan (`-sX`):** Se establecen múltiples banderas (FIN, URG, PUSH), iluminando el paquete como un "árbol de Navidad".

Según el estándar, si el puerto está **cerrado**, el *host* debe responder con un RST. Si el puerto está **abierto**, no debe responder. Esto permite a Nmap deducir el estado en entornos específicos.

## 4. Opciones (Banderas) Comunes

| Opción | Descripción | Detalle |
| :--- | :--- | :--- |
| **`-sS`** | Escaneo SYN (Stealth) | El más rápido y sigiloso. Requiere permisos de *root* (sudo). |
| **`-sT`** | Escaneo Connect | Escaneo completo de conexión. Más ruidoso, pero no requiere *root*. |
| **`-sU`** | Escaneo UDP | Escanea puertos basados en el protocolo UDP. Lento y complejo. |
| **`-sV`** | Detección de Versiones | Intenta determinar el nombre y la versión exacta del servicio. |
| **`-O`** | Detección de S.O. | Intenta determinar el sistema operativo del host de destino. |
| **`-p <rango>`** | Rango de Puertos | Especifica los puertos a escanear (ej. `-p 80,443` o `-p 1-1000`). |
| **`-A`** | Agresivo | Habilita la detección de OS (`-O`), la detección de versión (`-sV`), el escaneo de *scripts* (`-sC`) y el *traceroute*. |
| **`-T<0-5>`** | Control de Tiempo | Ajusta la velocidad del escaneo. `-T4` (Agresivo) es el más común y rápido. |
| **`-n`** | Sin Resolución DNS | Desactiva la resolución inversa de DNS (la salida solo muestra IPs), acelerando mucho el escaneo. |
| **`-iL <archivo>`** | Entrada de Lista | Carga una lista de hosts o redes desde un archivo. |

***

Perfecto.
Aquí tienes **la estructura correcta, completa y profesional** para `ft_nmap`, **sin darte código**, sólo arquitectura y responsabilidades.
Esta estructura cumple al 100% con el subject y evita errores comunes del proyecto.

---

# ✅ **ESTRUCTURA FINAL Y CORRECTA DEL PROYECTO `ft_nmap`**

Diseñada exactamente para:

* Parsing serio de argumentos
* Lectura de lista de IPs
* Soporte de rangos y listas de puertos
* Soporte múltiple de scans (SYN / NULL / FIN / XMAS / ACK / UDP)
* Uso de **threads** (0–250)
* Uso de **pcap** para capturar respuestas
* Formateo final EXACTO como el subject

---

# 📁 **ÁRBOL DEL PROYECTO**

```
ft_nmap/
│
├── Makefile
├── README.md
│
├── incl/
│   ├── ft_nmap.h
│   ├── args.h
│   ├── ports.h
│   ├── iplist.h
│   ├── scan_types.h
│   ├── scheduler.h
│   ├── pcap_capture.h
│   ├── packet_builder.h
│   ├── scan_exec.h
│   ├── results.h
│   ├── formatter.h
│   └── utils.h
│
└── src/
    ├── main.c
    │
    ├── args/
    │   ├── parse_args.c
    │   ├── parse_ports.c
    │   ├── parse_ip.c
    │   ├── parse_scan_types.c
    │   ├── parse_speedup.c
    │   └── validate_args.c
    │
    ├── data/
    │   ├── iplist.c
    │   ├── ports.c
    │   └── results.c
    │
    ├── scans/
    │   ├── scan_syn.c
    │   ├── scan_ack.c
    │   ├── scan_null.c
    │   ├── scan_fin.c
    │   ├── scan_xmas.c
    │   └── scan_udp.c
    │
    ├── network/
    │   ├── packet_builder.c
    │   ├── pcap_capture.c
    │   ├── send_raw_packet.c
    │   └── socket_setup.c
    │
    ├── threads/
    │   ├── scheduler.c
    │   └── worker_thread.c
    │
    ├── output/
    │   ├── formatter.c
    │   └── print_results.c
    │
    ├── utils/
    │   ├── time.c
    │   ├── service_lookup.c
    │   └── string_utils.c
    │
    └── help/
        └── print_help.c
```

---

# 🧩 **RESPONSABILIDADES DE CADA MÓDULO**

---

## 🔹 **1. main.c**

* Inicializa la estructura global del programa
* Llama al parser
* Prepara hilos
* Lanza escaneos
* Llama al formatter para imprimir resultados

---

## 🔹 **2. /incl — Headers**

Un header por módulo, sin includes cruzados innecesarios.

`ft_nmap.h` sólo contiene:

* includes estándar
* defines globales del proyecto
* structs centrales
* prototipos generales

---

## 🔹 **3. args/**

Toda la lógica de parsing:

### `parse_args.c`

* Recibe `argc/argv`
* Reconstruye tokens
* Detecta flags
* Llama a los sub-parsers

### `parse_ports.c`

* Procesa:

  * `1-100`
  * `80,443,8080`
  * mezcla `1-20,80,443`
* Garantiza:

  * máximo 1024 puertos
  * ordenación interna (opcional)

### `parse_ip.c`

* Gestiona `--ip`
* Resuelve hostnames **sin FQDN** (subject)
* Valida IPv4

### `parse_scan_types.c`

* Procesa `--scan SYN,XMAS,NULL`
* Si no se especifica: activa TODOS

### `parse_speedup.c`

* Valida 0–250 threads

### `validate_args.c`

* Comprueba combinaciones inválidas:

  * `--ip` y `--file` simultáneos → error
  * falta IP → error
  * speedup > 250 → error
  * puerto inválido → error

---

## 🔹 **4. data/**

### `iplist.c`

* Lee archivo de IPs
* Guarda lista dinámica de targets

### `ports.c`

* Gestiona array/lista de puertos
* Número total de puertos a escanear

### `results.c`

* Estructura con los resultados finales de cada scan por puerto:

  * open
  * closed
  * filtered
  * unfiltered
  * open|filtered

---

## 🔹 **5. scans/**

Un archivo por tipo de scan:

* `scan_syn.c`
* `scan_ack.c`
* `scan_null.c`
* `scan_fin.c`
* `scan_xmas.c`
* `scan_udp.c`

Cada uno:

* construye un paquete específico
* envía con `send_raw_packet`
* espera respuesta en pcap
* clasifica resultado según RFC

**NO mezclas lógica entre scans.**

---

## 🔹 **6. network/**

### `packet_builder.c`

* Construye cabeceras:

  * Ethernet (opcional)
  * IP
  * TCP
  * UDP

### `pcap_capture.c`

* Configura pcap
* Filtra por:

  * IP destino
  * puerto
  * flags TCP
* Timeout por puerto
* Devuelve la respuesta capturada

### `send_raw_packet.c`

* Envía el paquete RAW con `sendto`

### `socket_setup.c`

* Crea sockets RAW TCP/UDP
* Ajusta opciones (IP_HDRINCL)

---

## 🔹 **7. threads/**

### `scheduler.c`

* Divide puertos entre hilos
* Coordina estados
* Asegura:

  * no más de 250 hilos
  * reparto eficiente

### `worker_thread.c`

* Cada thread ejecuta:

  * por cada puerto:

    * por cada tipo de scan activado:

      * enviar paquete
      * esperar respuesta con pcap
      * guardar resultado

---

## 🔹 **8. output/**

### `formatter.c`

* Construye el formato EXACTO del subject:

  * lista de puertos abiertos
  * lista de puertos cerrados/filtered/unfiltered
  * por cada puerto muestra resultados por scan

### `print_results.c`

* Imprime tabla final
* Alinea columnas
* Ordena puertos

---

## 🔹 **9. utils/**

### `time.c`

* Medición de tiempo total del scan

### `service_lookup.c`

* Mapea:

  * 80 → http
  * 53 → domain
  * 443 → https

### `string_utils.c`

* splits, trims, parsers simples

---

## 🔹 **10. help/**

### `print_help.c`

* Muestra EXACTO el formato del subject

---

Perfecto. Aquí tienes **solo explicación**, sin código, cubriendo las **4 cosas** que pides entender de cómo funciona `nmap` y cómo debe funcionar tu `ft_nmap`.

---

# ✅ 1. Cómo funciona un comando `nmap` básico

`nmap` puede ejecutarse simplemente pasando un **objetivo**, sin ningún flag adicional:

* `nmap 8.8.8.8`
* `nmap scanme.nmap.org`
* `nmap localhost`

Esto hace que `nmap` use su **configuración por defecto**:

* Escaneo TCP SYN
* Escaneo de los 1000 puertos más comunes
* Detección básica del host

**Conclusión:**
Nmap permite lanzar un escaneo solo indicando el destino.

---

# ✅ 2. Cómo funcionan los flags u opciones de `nmap`

Los flags modifican el comportamiento del escaneo. Ejemplos reales:

* `-p 80` → puerto 80
* `-p 20-80` → rango
* `-sS` → SYN scan
* `--top-ports 20` → los 20 más comunes
* `-T4` → velocidad
* `-A` → detección avanzada
* `-v` → verbose

**Conclusión:**
El usuario debe poder poner:

* solo flags
* flags + objetivo
* objetivo + flags
  en cualquier orden.

---

# ✅ 3. Qué hace Nmap cuando se mezclan objetivos + opciones

Ejemplos típicos:

* `nmap -p 80 8.8.8.8`
* `nmap 192.168.1.0/24 -sn`
* `nmap -sS -T4 scanme.nmap.org`

**Patrón general:**
`nmap [opciones] <objetivo> [más opciones opcionales]`

Nmap permite:

* un objetivo al final
* uno al principio
* varios objetivos
* redes enteras

**Conclusión:**
Tu `ft_nmap` puede simplificar esto, pero Nmap es flexible.

---

# ✅ 4. ¿Cómo debería funcionar tu `ft_nmap`? (versión simplificada del proyecto)

Tu implementación está diseñada para aceptar flags **tipo GNU largo**, todos opcionales excepto `--ip`.

Tu uso ideal sería:

```
ft_nmap --ip 8.8.8.8
ft_nmap --ip scanme.nmap.org --ports 80
ft_nmap --ip 10.0.0.1 --ports 1-100 --speedup 5 --scan SYN
```

Tus opciones significan:

### ✔ `--ip <address>`

Obligatoria.
Es el destino del escaneo.
Es el equivalente simplificado del “objetivo” de nmap.

### ✔ `--ports <ports>`

Opcional.

* Puede ser un puerto
* un rango
* una lista
* o “all”

### ✔ `--speedup <number>`

Opcional.
Número de hilos (o workers).
Equivalente simplificado a `-T` de Nmap.

### ✔ `--scan <type>`

Opcional.
Por ejemplo: SYN, NULL, FIN, XMAS.

**Tu programa funciona así a propósito:**

* Sin argumentos → mensaje de ayuda.
* Con `--help` → manual.
* Con `--ip` como mínimo → empieza el escaneo.

---

# 📌 Síntesis final

Para tu proyecto debes comprender esto:

### 🔹 **Nmap real**

* Permite usar solo el objetivo.
* Permite escaneos complejos.
* Admite flags en cualquier orden.

### 🔹 **Tu ft_nmap**

* Necesita **--ip** obligatoriamente.
* Tiene flags largos estilo GNU.
* El diseño está simplificado para el proyecto de 42.
* No hace falta replicar la sintaxis exacta de Nmap real.

---
