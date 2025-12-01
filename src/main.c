#include "ft_nmap.h"

volatile sig_atomic_t   g_stop = 0;

void    cleanup(t_config *conf)
{
    if (conf->ports != NULL)
        free(conf->ports);
    free(conf);
}

int main(int argc, char **argv)
{
    t_config    *conf;
    int         exit = 0;

    if (argc == 1)
    {
        printf("%s Usage: --ip <IPv4 | hostname> [--ports <range/list>] [--scan <types>] [--speedup <n>]\n", argv[0]);
        printf("Try --help for more information.\n");
        return (1);
    }

    conf = malloc(sizeof(t_config));
    if (!conf)
        return (1);
    init_signal();
    init_struct(conf, argc);
    if (ft_parser_args(conf, argv) != 0)
        exit = 1;
    if (conf->show_help)
        show_help();
    else if (dns_resolution(conf) != 0)
        exit = 1;
    while (!g_stop && exit == 0 && !conf->show_help)
    {
        printf("ip: ( %s )\n", conf->hostname);
        printf("PARA EL BUCLE `CON Control + C'\n");
        sleep (2);
        if (g_stop == 1)
            printf("SEÑAL RECIBIDA\n");
    }
    
    cleanup(conf);
    return (exit);
}


// 1. Parseo (YA HECHO)

// ✔ validar argumentos
// ✔ expandir puertos
// ✔ seleccionar tipos de escaneo
// ✔ calcular speedup
// ✔ warning de oversubscription

// 2. Resolución de DNS / IP

// ✔ hostname → IP
// ✔ verificar que es válida
// ✔ preparar sockaddr con la IP final

// 3. Preparar contexto de escaneo

// ✔ tabla de puertos
// ✔ estructuras de hilos
// ✔ colas de trabajo
// ✔ flags TCP según el tipo de escaneo

// 4. Crear el pool de hilos

// ✔ speedup = nº de hilos
// ✔ cada hilo toma puertos en paralelo
// ✔ sincronización mínima (mutex opcional)

// 5. Crear sockets RAW (o uno por hilo según tu diseño)

// ✔ socket(AF_INET, SOCK_RAW, protocolo)
// ✔ setear IP_HDRINCL si construyes headers
// ✔ configurar timeouts

// 6. Enviar paquetes y analizar respuestas

// ✔ SYN → SYN/ACK / RST
// ✔ NULL / FIN / XMAS → RST / no-response
// ✔ UDP → ICMP Port Unreachable / open|filtered

// 7. Imprimir tabla final de resultados

// ✔ ordenadores por puerto
// ✔ estado por cada tipo de scan