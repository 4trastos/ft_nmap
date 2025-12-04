#include "ft_nmap.h"

volatile sig_atomic_t   g_stop = 0;

void    cleanup(t_config *conf)
{
    if (!conf)
        return;
    if (conf->ports != NULL)
        free(conf->ports);
    free(conf);
}

int main(int argc, char **argv)
{
    t_config            *conf;
    t_thread_context    *threads;
    unsigned char       *bytes;
    int                 exit = 0;

    if (argc == 1)
    {
        printf("%s Usage: --ip <IPv4 | hostname> [--ports <range/list>] [--scan <types>] [--speedup <n>]\n", argv[0]);
        printf("Try --help for more information.\n");
        return (1);
    }

    conf = malloc(sizeof(t_config));
    if (!conf)
        return (1);
    threads = malloc(sizeof(t_thread_context));
    if (!threads)
    {
        free(conf);
        return (1);
    }

    init_signal();
    init_struct(conf, argc);

    if (ft_parser_args(conf, argv) != 0)
        exit = 1;
    if (conf->show_help)
    {
        show_help(conf);
        return(0);
    }
    else if (dns_resolution(conf) != 0)
        exit = 1;
    else if (socket_creation(conf) != 0)
        exit = 1;
    else
    {
        ft_mutex(threads->work_mutex, INIT);
        ft_mutex(conf->work_mutex, INIT);
        if (threads_creation(threads, conf) != 0)
        {
            cleanup(conf);
            free(threads);
            ft_mutex(threads->work_mutex, DESTROY);
            ft_mutex(conf->work_mutex,DESTROY);
            return (1);
        }
        worker_thread(threads);
        bytes = (unsigned char *)&conf->ip_address;
        printf("Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-12-03 12:08 CET\n");
        printf("Nmap scan report for %s (%d.%d.%d.%d)\n", conf->hostname, bytes[0], bytes[1], bytes[2], bytes[3]);
        ft_mutex(threads->work_mutex, DESTROY);
        ft_mutex(conf->work_mutex, DESTROY);
    }
    cleanup(conf);
    free(threads);
    return (exit);
}

// 6. Lanzar threads

// Crear conf->speedup hilos

// Cada hilo ejecuta:
// worker_thread(void *arg)

// 7. Esperar a los threads

// Usar pthread_join()

// Si Ctrl+C ocurre, g_stop hace que los threads terminen solos.

// 8. Imprimir resultados finales

// Resultado general por host:

// Dirección IP

// Hostname

// Por cada puerto:

// abierto / cerrado / filtrado + tipo de scan

// 9. Limpieza

// Liberar:

// conf->ports

// conf->threads

// conf

// Cerrar socket