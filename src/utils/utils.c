#include "ft_nmap.h"

int count_ports(char *str)
{
    char a = '-';
    char b = ',';
    int i = 0;
    int result = 0;

    while (str[i] != '\0')
    {
        if (str[i] == a || str[i] == b)
            result++;
        i++;
    }
    return (result + 1);
}

char    *ft_strndup(char *str, int num)
{
    char    *new = NULL;
    int     i = 0;

    new = malloc(num + 1);
    if (!new)
        return (NULL);
    while (i < num)
    {
        new[i] = str[i];
        i++;
    }
    new[i] = '\0';
    return (new);
}

void    double_free(char **str)
{
    int     i = 0;

    while (str[i])
    {
        free(str[i]);
        i++;
    }
    free(str);
    return;
}