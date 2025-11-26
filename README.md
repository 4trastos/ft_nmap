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