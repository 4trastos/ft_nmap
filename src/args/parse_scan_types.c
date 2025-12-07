#include "ft_nmap.h"

char    **split_scan(char *str, char c)
{
    char    **new;
    int     i;
    int     x;
    int     memo;
    int     tokens;

    tokens = count_tokens(str);
    new = malloc(sizeof(char *) * (tokens + 1));
    if (!new)
        return (NULL);
    x = 0;
    i = 0;
    while (x < tokens && str[i] != '\0')
    {
        memo = i;
        while (str[i] != c && str[i] != '\0')
            i++;
        new[x] = ft_strndup(&str[memo], (i - memo));
        if (str[i] == c)
            i++;
        x++;
    }
    new[x] = NULL;
    return (new);
}

int     parse_scantypes(t_config *conf, char **argv, int i)
{
    char    *arg_value = NULL;
    char    **tokens = NULL;
    int     x = 0;
    int     scan_flags = 0;

    if (i + 1 >= conf->argc || !(argv[i + 1][0] >= 65 && argv[i + 1][0] <= 90))
    {
        printf("Option `--scan' (argc %d) requires an argument: `--scan <type>'\n", i);
        return (-1);
    }
    arg_value = argv[i + 1];

    while (arg_value[x] != '\0')
    {
        if (!((arg_value[x] >= 65 && arg_value[x] <= 90) || arg_value[x] == ','))
        {
            printf("❌ Error: `--scan' You have used an invalid format: ( \"%s\" )\n", arg_value);
            return (-1);
        }
        x++;
    }
    x--;
    if (arg_value[x] == ',')
    {
        printf("❌ Error: `--scan' You have used an invalid format: ( \"%s\" )\n", arg_value);
        return (-1);
    }
    
    tokens = split_scan(arg_value, ',');
    if (!tokens)
        return (-1);
    x = 0;
    while (tokens[x] != NULL)
    {
        if (strcmp(tokens[x], "SYN") == 0)
            scan_flags |= SCAN_SYN;
        else if (strcmp(tokens[x], "NULL") == 0)
            scan_flags |= SCAN_NULL;
        else if (strcmp(tokens[x], "FIN") == 0)
            scan_flags |= SCAN_FIN;
        else if (strcmp(tokens[x], "XMAS") == 0)
            scan_flags |= SCAN_XMAS;
        else if (strcmp(tokens[x], "ACK") == 0)
            scan_flags |= SCAN_ACK;
        else if (strcmp(tokens[x], "UDP") == 0)
            scan_flags |= SCAN_UDP;
        else
        {
            printf("❌ Error: `--scan' invalid scan type: \"%s\"\n", tokens[x]);
            double_free(tokens);
            return (-1);
        }
        x++;
    }
    
    conf->scan_type = scan_flags;
    if (conf->scan_type == 0)
        conf->scan_type = SCAN_SYN | SCAN_NULL | SCAN_FIN | SCAN_XMAS | SCAN_ACK | SCAN_UDP;
    double_free(tokens);
    return (1);
}