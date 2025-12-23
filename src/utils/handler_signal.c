#include "ft_nmap.h"

void    init_signal(void)
{
    struct sigaction sa;

    sa.sa_handler = handler_singint;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sigaction(SIGINT, &sa, NULL);
}

void    handler_singint(int signum)
{
    (void)signum;
    g_stop = 1;
}