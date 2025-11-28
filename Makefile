NAME = ft_nmap
CC = gcc
CFLAGS = -Wall -Wextra -Werror -g -Iincl
LDFLAGS = -lm -lc
LDLIBS = -lpcap -lpthread
RM = rm -f

SRC = src/main.c src/args/parser_args.c src/help/show_help.c src/args/parse_ports.c src/args/parse_ip.c src/args/parse_scan_types.c \
	src/args/parse_speedup.c src/args/validate_args.c src/data/iplist.c src/data/ports.c src/data/results.c src/scans/scan_syn.c \
	src/scans/scan_ack.c src/scans/scan_fin.c src/scans/scan_null.c src/scans/scan_xmas.c src/scans/scan_udp.c src/network/packet_builder.c \
	src/network/pcap_capture.c src/network/send_raw_packet.c src/network/socket_setup.c src/threads/scheduler.c src/threads/worker_thread.c \
	src/output/formatter.c src/output/print_results.c src/utils/time.c src/utils/service_lookup.c src/utils/string_utils.c src/utils/handler_signal.c

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