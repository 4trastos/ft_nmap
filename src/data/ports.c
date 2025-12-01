#include "ft_nmap.h"

int     find_dash(char *str)
{
    int i = 0;
    int script = 0;

    while (str[i] != '\0')
    {
        if (str[i] == '-')
            script++;
        i++;
    }
    return (script);
}

int validate_range(const char *token, int *start, int *end)
{
    char    *left = NULL;
    char    *right = NULL;
    int     limit = 0;
    int     len_left;
    char    *dash = NULL;

    dash = strchr(token, '-');
    if (!dash)
        return (-1);

    len_left = dash - token;
    left = ft_strndup((char *)token, len_left);
    if (!left)
        return (-1);
    right = strdup(dash + 1);
    if (!right)
    {
        free(left);
        return (-1);
    }

    if (*right == '\0')
    {
        free(left);
        free(right);
        return (-1);
    }
    *start = ft_atoi_dav(left, &limit);
    if (limit != 0 || right[0] == '0')
    {
        free(left);
        free(right);
        return (-1);
    }

    *end = ft_atoi_dav(right, &limit);
    if (*start < 0 || *end > 65535 || *start > *end || limit != 0)
    {
        free(left);
        free(right);
        return (-1);
    }

    free(left);
    free(right);
    return (0);
}

int     port_validator(t_config *conf, char **tokens)
{
    char    *token;
    int     i = 0;
    int     dash = 0;
    int     start = 0;
    int     end = 0;   
    int     port = 0;
    int     limit = 0;

    /* 1- Expandri y validar */
    
    while (tokens[i] != NULL && i < conf->ports_tokens)
    {
        token = tokens[i];
        dash = find_dash(tokens[i]);
        if (dash)
        {
            if (dash > 1)
                return (-1);
            if (validate_range(token, &start, &end) != 0)
            {
                printf("❌ Error: invalid port range \"%s\"\n", token);
                return (-1);
            }
            for (port = start; port <= end; port++)
                conf->port_bitmap[port] = 1;
            
        }
        else
        {
            port = ft_atoi_dav(token, &limit);
            if (port < 0 || port > 65535 || limit != 0)
            {
                printf("❌ Error: `--port' out of range: ( %d )\n", port);
                return (-1);
            }
            conf->port_bitmap[port] = 1;
        }
        i++;
    }

    /* 2. Contar los puertos */

    i = 0;
    port = 0;
    while (port < 65536)
    {
        if (conf->port_bitmap[port] == 1)
            i++;
        port++;
    }
    conf->total_ports = i;

    conf->ports = malloc(sizeof(t_port) * conf->total_ports);
    if (!conf->ports)
        return(-1);

    i = 0;
    port = 0;
    while (port < 65536)
    {
        if (conf->port_bitmap[port] == 1)
            conf->ports[i++].number = port;
        port++;
    }

    return (0);
}