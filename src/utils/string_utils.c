#include "ft_nmap.h"

int     ft_strlen(char *str)
{
    int i = 0;
    while (str[i] != '\0')
        i++;
    return (i);
}

char	*ft_substr(char *str, int start, int len)
{
    char    *new;
    int     i = 0;

    new = malloc(len + 1);
    if (!new)
        return (NULL);
    while (i < len)
    {
        new[i] = str[start];
        i++;
        start++;
    }
    new[i] = '\0';
    return (new);
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