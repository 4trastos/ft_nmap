#include "ft_nmap.h"

int socket_creation(t_config *conf)
{
    struct  timeval timeout = {4, 0};
    
    conf->sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (conf->sockfd == -1)
    {
        if (errno == EPERM)
        {
            printf("ft_nmap: socket error ( %s ) - Must be root.\n", strerror(errno));
            return (-1);
        }
        printf("ft_namp: socket error: %s\n", strerror(errno));
        return (-1);
    }
    if (setsockopt(conf->sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == -1)
    {
        printf("ft_nmap: setsockopt (SO_RCVTIMEO): %s\n", strerror(errno));
        close(conf->sockfd);
        return (-1);
    }

    return (0);
}