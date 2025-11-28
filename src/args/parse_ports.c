#include "ft_nmap.h"

// 80
// 1-100
// 22,80,443
// 1-10,20,80-90

char    **split_ports(char *str, t_config *conf)
{
    char    **ports;
    int     i = 0;
    int     x = 0;
    int     memo = 0;

    ports = malloc(sizeof(char *) * (count_ports(str) + 1));
    if (!ports)
        return (NULL);
    conf->ports_number = count_ports;
    while (x < count_ports(str) && str[i] != '\0')
    {
        memo = i;
        while (str[i] != '-' && str[i] != ',' && str[i] != '\0')
            i++;
        ports[x] = ft_strndup(&str[memo], i - memo);
        x++;
    }
    ports[x] = NULL;
    return (ports);
}

int parse_ports(t_config *conf, char **argv, int i)
{
    char        **ports = NULL;
    char  *arg_value = NULL;
    int         x = 0;

    if (strcmp(argv[i], "--ports") == 0)
    {
        if (i + 1 >= conf->argc)
        {
            printf("Option `--ports' (argc %d) requires an argument: `--ports <ports>'\n", i);
            return (-1);
        }
        arg_value = argv[i + 1];
        while (arg_value[x] != '\0')
        {
            if (arg_value[x] >= '0' && arg_value[x] <= '9')
                x++;
            else if (x != 0 && (arg_value[x] == '-' || arg_value[x] == ','))
            {
                if (arg_value[x + 1] == '-' || arg_value[x + 1] == ',')
                    return (-1);
                x++;
            }
            else
                return (-1);
        }
        x--;
        if (arg_value[x] == '-' || arg_value[x] == ',')
            return (-1);
    }
    ports = split_ports(arg_value, conf);
    if (!ports)
        return (-1);
    return (1);
}

/* COSAS POR HACER */

// que los números estén en rango (0–65535)

// que 1-100 tenga sentido (inicio < fin)

// que ,-- no aparezcan dos veces seguidas

// que no empiece o termine con coma o guion

// que no haya "80-", "80,,22", "--", etc.

// que la lista esté bien formateada

// que no mezcle cosas imposibles (100-1)

// que no haya espacios ("80 , 22")