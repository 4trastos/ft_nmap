NAME = ft_nmap
CC = gcc
CFLAGS = -Wall -Wextra -Werror -g -Iincl
LDFLAGS = -lm
LDLIBS = -lpcap -lpthread
RM = rm -f

SRC = src/main.c src/parser.c

OBJTS = $(SRC:.c=.o)

all: $(NAME)

$(NAME): $(OBJTS)
	$(CC) $(CFLAGS) -o $(NAME) $(OBJTS) $(LDFLAGS) $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	$(RM) $(OBJTS)

fclean: clean
	$(RM) $(NAME)

re: all

PHONY: all clean fclean re