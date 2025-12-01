#include "ft_nmap.h"

// 80
// 1-100
// 22,80,443
// 1-10,20,80-90

int count_tokens(char *str)
{
    int i = 0;
    int count = 1;

    while (str[i] != '\0')
    {
        if (str[i] == ',')
            count++;
        i++;
    }
    return (count);
}

char    **split_tokens(char *str, t_config *conf)
{
    char    **ports;
    int     i = 0;
    int     x = 0;
    int     memo = 0;

    conf->ports_tokens = count_tokens(str);
    if (conf->ports_tokens > 1024)
    {
        printf("❌ Error: `--port' out of range: ( %d )\n", conf->ports_tokens);
        return (NULL);
    }
    ports = malloc(sizeof(char *) * (conf->ports_tokens + 1));
    if (!ports)
        return (NULL);
    while (x < conf->ports_tokens && str[i] != '\0')
    {
        memo = i;
        while (str[i] != ',' && str[i] != '\0')
            i++;
        ports[x] = ft_strndup(&str[memo], i - memo);
        if (str[i] == ',')
            i++;
        x++;
    }
    ports[x] = NULL;
    return (ports);
}

int parse_ports(t_config *conf, char **argv, int i)
{
    char        **tokens = NULL;
    char        *arg_value = NULL;
    int         x = 0;


    if ((i + 1 >= conf->argc) || (argv[i+ 1][0] == '-'))
    {
        printf("Option `--ports' (argc %d) requires an argument: `--ports <ports>'\n", i);
        return (-1);
    }

    arg_value = argv[i + 1];

    if (arg_value[0] == '0')
    {
        printf("❌ Error: `--port' You have used an invalid format: ( \"%s\" )\n", arg_value);
        return (-1);
    }
    while (arg_value[x] != '\0')
    {
        if (arg_value[x] >= '0' && arg_value[x] <= '9')
            x++;
        else if (x != 0 && (arg_value[x] == '-' || arg_value[x] == ','))
        {
            if (arg_value[x + 1] == '-' || arg_value[x + 1] == ',')
            {
                printf("❌ Error: `--port' You have used an invalid format: ( \"%s\" )\n", arg_value);
                return (-1);
            }
            x++;
        }
        else
        {
            printf("❌ Error: `--port' You have used an invalid format: ( \"%s\" )\n", arg_value);
            return (-1);
        }
    }
    x--;
    if (arg_value[x] == '-' || arg_value[x] == ',')
    {
        printf("❌ Error: `--port' You have used an invalid format: ( \"%s\" )\n", arg_value);
        return (-1);
    }
    
    tokens = split_tokens(arg_value, conf);
    if (!tokens)
        return (-1);
    if (port_validator(conf, tokens) != 0)
    {
        double_free(tokens);
        return (-1);
    }
    double_free(tokens);
    return (1);
}
