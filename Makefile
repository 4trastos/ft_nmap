NAME = ft_nmap
CC = gcc
CFLAGS = -Wall -Wextra -Werror -g -Iincl
RM = rm -f

SRC = src/main.c src/parser.c
OBJTS = $(SRC:.c=.o)

all: $(NAME)