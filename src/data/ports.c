#include "ft_nmap.h"

int     find_scripts(char *str)
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

int    validate_range(t_config *conf, char *token)
{
    char    *start = NULL;
    char    *end = NULL;
    int     i = 0;

    while (token[i] != '\0')
    {
        if (token[i] == '-')
        {
            start = ft_substr(token, 0, i);
            end = ft_substr(token, i + 1, (strlen(token) - (i + 1)));
            break;
        }
        i++;
    }
    conf->start_port = atoi(start);
    conf->end_port = atoi(end);
    free(start);
    free(end);
    if (conf->start_port > conf->end_port)
        return (-1);
    if (conf->start_port >= 0 && conf->end_port <= 65535)
        return (0);
    return (-1);
}

int     port_validator(t_config *conf, char **token)
{
    int     i = 0;
    int     script = 0;
    int     port = 0;
    
    conf->ports = malloc(sizeof(t_port) * (conf->ports_tokens + 1));
    if (!conf->ports)
        return(-1);

    while (token[i] != NULL && i < conf->ports_tokens)
    {
        script = find_scripts(token[i]);
        if (script)
        {
            if (script > 1)
                return (-1);
            if (validate_range(conf, token[i]) != 0)
            {
                printf("❌ Error: `--port' out of range: ( %d )\n", conf->end_port);
                return (-1);
            }
            conf->ports[i].start_port = conf->start_port;
            conf->ports[i].end_port = conf->end_port;
            conf->ports[i].number = conf->start_port;
        }
        else
        {
            port = atoi(token[i]);
            if (port >= 0 && port <= 65535)
            {
                conf->ports[i].start_port = port;
                conf->ports[i].end_port = port;
                conf->ports[i].number = port;
            }
            else
            {
                printf("❌ Error: `--port' out of range: ( %d )\n", port);
                return (-1);
            }
        }
        i++;
    }  
    return (0);
}