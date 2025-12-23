#include "ft_nmap.h"

void    ft_mutex(t_mutex *mutex, t_opcode opcode)
{
    if (opcode == LOCK)
        pthread_mutex_lock(mutex);
    else if (opcode == UNLOCK)
        pthread_mutex_unlock(mutex);
    else if (opcode == INIT)
        pthread_mutex_init(mutex, NULL);
    else if (opcode == DESTROY)
        pthread_mutex_destroy(mutex);
    else
        printf("🚨 Wrong opcode for mutex handle use <LOCK> <UNLOCK> <INIT> <DESTROY> 🚨\n");
}
