#include "ft_nmap.h"

int parse_file(t_config *conf, char **argv, int i)
{
    char    *arg_value = NULL;

    if (conf->file_input != NULL)
    {
        printf("%s: Error: Only one file is allowed\n", argv[i + 1]);
        return (-1);
    }

    if ((i + 1 >= conf->argc) || (argv[i + 1][0] == '-'))
    {
        printf("Option `--file' (argc %d) requires a filename\n", i);
        return (-1);
    }
    arg_value = argv[i + 1];
    conf->file_input = arg_value;
    return (1);
}