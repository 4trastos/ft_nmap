#include "ft_nmap.h"

int	ft_atoi_dav(char *str, int *limit)
{
	int				i;
	int				result;
	long long int	number;

	number = 0;
	i = 0;
	result = 1;
	if (str[i] == '-' || str[i] == '+')
	{
		if (str[i] == '-')
			result = -1;
		i++;
	}
	while (str[i] >= '0' && str[i] <= '9')
	{
		number = number * 10 + str[i] - '0';
		i++;
		if (number > ((long long int)INT_MAX + 1) && result == -1)
			*limit = 1;
		if (number > INT_MAX && result == 1)
			*limit = 1;
	}
	return (number * result);
}