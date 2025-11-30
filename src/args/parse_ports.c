#include "ft_nmap.h"

// 80
// 1-100
// 22,80,443
// 1-10,20,80-90

int count_tokens(char *str)
{
    char b = ',';
    int i = 0;
    int result = 0;

    while (str[i] != '\0')
    {
        if (str[i] == b)
            result++;
        i++;
    }
    return (result + 1);
}

char    **split_tokens(char *str, t_config *conf)
{
    char    **ports;
    int     i = 0;
    int     x = 0;
    int     memo = 0;

    ports = malloc(sizeof(char *) * (count_tokens(str) + 1));
    if (!ports)
        return (NULL);
    conf->ports_tokens = count_tokens(str);
    while (x < conf->ports_tokens && str[i] != '\0')
    {
        memo = i;
        while (str[i] != ',' && str[i] != '\0')
            i++;
        ports[x] = ft_strndup(&str[memo], i - memo);
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

    if (strcmp(argv[i], "--ports") == 0)
    {
        if ((i + 1 >= conf->argc) || (argv[i+ 1][0] == '-'))
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
            return (-1);
    }
    tokens = split_tokens(arg_value, conf);
    if (!tokens)
        return (-1);
    if (port_validator(conf, tokens) != 0)
        return (-1);
    double_free(tokens);
    return (1);
}
