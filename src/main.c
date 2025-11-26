#include "ft_nmap.h"

int main(int argc, char **argv)
{
    struct config   *conf;
    int             exit = 0;

    if (argc == 1)
    {
        printf("%s [--help] [--ports [NUMBER/RANGED]] --ip IP_ADDRESS [--speedup [NUMBER]] [--scan [TYPE]]\n", argv[0]);
        return (1);
    }

    conf = malloc(sizeof(struct config));
    if (!conf)
        return (1);
    
    init_struct(conf);
    if (ft_parser(conf, argv) != 0)
        exit = 1;
    return (exit);
}