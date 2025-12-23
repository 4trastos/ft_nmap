NAME = ft_nmap
CC = gcc
CFLAGS = -Wall -Wextra -Werror -g -Iincl
LDFLAGS = -lm -lc
LDLIBS = -lpcap -lpthread
RM = rm -f

SRC = src/main.c src/args/parser_args.c src/help/show_help.c src/args/parse_ports.c src/args/parse_ip.c src/args/parse_scan_types.c \
	src/args/parse_speedup.c src/data/ports.c src/data/results.c src/network/network_scan.c src/threads/threads.c src/threads/sequential_scan.c \
	src/network/packet_builder.c src/network/socket_setup.c src/threads/multi_thread.c src/utils/ft_atoi.c src/data/scan_ports.c\
	src/utils/string_utils.c src/utils/handler_signal.c

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

re: fclean all 

PHONY: all clean fclean re