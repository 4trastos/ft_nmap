#include "ft_nmap.h"

int dns_resolution(t_config *conf)
{
    struct addrinfo     hints;
    struct addrinfo     *result;
    struct addrinfo     *aux;
    struct sockaddr_in  *ipv4;
    int             status;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = 0; 
    hints.ai_protocol = 0;        
    hints.ai_flags = 0; 

    status = getaddrinfo(conf->hostname, NULL, &hints, &result);
    if (status != 0)
    {
        printf("❌ Error: Obtaining the host: ( %s ) ❌\n", gai_strerror(status));
        freeaddrinfo(result);
        return (-1);
    }

    aux = result;
    while (aux != NULL)
    {
        if (aux->ai_family == AF_INET)
        {
            ipv4 = (struct sockaddr_in *)aux->ai_addr; 
            conf->ip_address = ipv4->sin_addr;
            freeaddrinfo(result);
            return (0);
        }
        aux = aux->ai_next;
    }
    
    printf("❌ Error: no IPv4 address found\n");
    freeaddrinfo(result);
    return (-1);
}

int parse_ip(t_config *conf, char **argv, int i)
{
    if (conf->hostname != NULL)
    {
        printf("%s: Error: Only one hostname is allowed\n", argv[0]);
        return (-1);
    }
    if (strcmp(argv[i], "--ip") == 0)
    {
        if ((i + 1 >= conf->argc) || (argv[i+ 1][0] == '-'))
        {
            printf("Option `--ip' (argc %d) requires an argument: `--ip <IPv4 | hostname>'\n", i);
            return (-1);
        }
        conf->hostname = argv[i + 1];
        if (conf->hostname[0] == '-')
            return (-1);
    }
    return (1);
}