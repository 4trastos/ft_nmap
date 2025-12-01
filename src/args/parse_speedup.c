#include "ft_nmap.h"

// cat /proc/cpuinfo | grep processor | wc -l

int     parse_speedup(t_config *conf, char **argv, int i)
{
    char    *arg_value = NULL;
    int     x = 0;
    int     limit = 0;
    
    if (strcmp(argv[i], "--speedup") == 0)
    {
        if ((i + 1 >= conf->argc) || (argv[i+ 1][0] == '-'))
        {
            printf("Option `--speedup' (argc %d) requires an argument: `--speedup <number>'\n", i);
            return (-1);
        }
        arg_value = argv[i + 1];
        if (arg_value[x] == '0')
        {
            printf("❌ Error: `--speedup' You have used an invalid format: ( \"%s\" )\n", arg_value);
            return (-1);
        }

        while (arg_value[x] != '\0')
        {
            if (arg_value[x] >= '0' && arg_value[x] <= '9')
                x++;
            else
            {
                printf("❌ Error: `--speedup' You have used an invalid format: ( \"%s\" )\n", arg_value);
                return (-1);
            }
        }
        conf->speedup = ft_atoi_dav(arg_value, &limit);
        if (limit == 1 || conf->speedup == 0 || conf->speedup > 250)
        {
            if (limit == 1)
                printf("❌ Error: `--speedup' exceeds INT_MAX: ( \"%s\" )\n", arg_value);
            else if (conf->speedup == 0 || conf->speedup > 250)
                printf("❌ Error: `--speedup' You have used an invalid format: ( \"%s\" )\n", arg_value);
            return (-1);
        }
    }

    conf->nprocs = sysconf(_SC_NPROCESSORS_ONLN);
    if (conf->speedup > conf->nprocs)
        printf("⚠️  WARNING ⚠️ : Requested --speedup %d worker threads on a machine with %ld physical cores. \nThis is allowed (subject supports up to 250 threads), but CPU oversubscription may slow down the scan.\n\n", 
            conf->speedup, conf->nprocs);

    return (1);
}