# ft_nmap

Proyecto de reimplementación parcial de **Nmap**, desarrollado en C, enfocado al
escaneo de puertos mediante distintos tipos de paquetes y al análisis de las
respuestas de red.

El objetivo principal es comprender en profundidad:

- El funcionamiento del stack TCP/IP
- El uso de sockets RAW
- La captura de tráfico con libpcap
- La concurrencia mediante threads
- La clasificación de estados de puertos según RFC

---

## 📌 Funcionalidades implementadas

- Parsing completo de argumentos
- Soporte de rangos y listas de puertos
- Escaneo de múltiples tipos simultáneamente
- Envío de paquetes TCP/UDP personalizados
- Captura centralizada de respuestas con **pcap**
- Escaneo secuencial o multithread
- Clasificación de puertos según el tipo de scan
- Gestión limpia de señales y recursos

---

## 🔍 Tipos de scan soportados

Los tipos de scan se pueden combinar mediante flags:

- **SYN scan**
- **NULL scan**
- **FIN scan**
- **XMAS scan**
- **ACK scan**
- **UDP scan**

La lógica de cada scan está separada y se apoya en un
constructor de paquetes común.

---

## 🧵 Modelo de concurrencia

El proyecto soporta escaneo:

- **Secuencial**
- **Multithread (speedup configurable)**

Arquitectura adoptada:

1. Un hilo central captura paquetes con **libpcap**
2. Los paquetes se distribuyen internamente según el contexto del scan
3. Cada worker procesa únicamente los paquetes que le corresponden

Este modelo evita duplicaciones de captura y replica el comportamiento real de
herramientas como Nmap.

---

## 📂 Estructura del proyecto

```

ft_nmap/
├── Makefile
├── README.md
├── test_ft_nmap.sh
│
├── incl/
│   └── ft_nmap.h
│
├── doc/
│   └── defence.txt
│
└── src/
├── main.c
│
├── args/
│   ├── parser_args.c
│   ├── parse_ip.c
│   ├── parse_ports.c
│   ├── parse_scan_types.c
│   └── parse_speedup.c
│
├── data/
│   ├── ports.c
│   ├── scan_ports.c
│   └── results.c
│
├── network/
│   ├── socket_setup.c
│   ├── packet_builder.c
│   └── network_scan.c
│
├── threads/
│   ├── threads.c
│   ├── multi_thread.c
│   └── sequential_scan.c
│
├── utils/
│   ├── ft_atoi.c
│   ├── string_utils.c
│   └── handler_signal.c
│
└── help/
└── show_help.c

````

---

## ⚙️ Compilación

```bash
make
````

---

## ▶️ Ejecución

Requiere permisos de superusuario para el uso de sockets RAW. Recomiendo levantar un kernel con docker:

```bash
docker run -it --rm --cap-add=NET_RAW -v "$(pwd):/workspace" -w /workspace \
  ubuntu:24.04 bash -c "apt update && apt install -y build-essential iproute2 traceroute nmap libpcap-dev gdb valgrind && bash"
```

Ejemplo:

```bash
./ft_nmap --ip 192.168.1.1 --ports 1-1024 --scan SYN,UDP --speedup 10
```

---

## 🧪 Tests

El proyecto incluye un script de pruebas básicas:

```bash
./test_ft_nmap.sh
```

---

## 🐛 Depuración

Recomendado usar **valgrind** para comprobar fugas de memoria:

```bash
valgrind --leak-check=full --show-leak-kinds=all ./ft_nmap [args]
```

---

## 📚 Documentación adicional

* `doc/defence.txt`
  Notas para defensa oral y decisiones técnicas del proyecto.

---

## 🧠 Notas finales

Este proyecto no busca replicar Nmap en su totalidad, sino implementar
de forma rigurosa los mecanismos fundamentales del escaneo de red,
respetando las normas de los protocolos y una arquitectura limpia y mantenible.

---


