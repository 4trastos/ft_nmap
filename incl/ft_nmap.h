#ifndef FT_NMAP_H
# define FT_NMAP_H

# include <string.h>
# include <stdlib.h>
# include <unistd.h>
# include <stdio.h>
# include <stdbool.h>
# include <ctype.h>
# include <errno.h>
# include <signal.h>
# include <pthread.h>
# include <limits.h>
# include <sys/types.h>
# include <sys/socket.h>
# include <sys/time.h>
# include <sys/un.h>
# include <netdb.h>
# include <netinet/in.h>
# include <netinet/ip.h>
# include <netinet/tcp.h>
# include <netinet/ip_icmp.h>
# include <netinet/udp.h>
# include <netinet/tcp.h>
# include <arpa/inet.h>
# include <pcap.h> 


# define    MAX_PACKET_SIZE 1500
# define    ICMP_PAYLOAD_SIZE 56

extern volatile sig_atomic_t   g_stop;

typedef pthread_mutex_t t_mutex;

typedef struct s_packet_node
{
    const u_char            *packet;
    struct pcap_pkthdr      header;
    struct s_packet_node    *next;
} t_packet_node;

typedef struct s_packet_queue
{
    t_packet_node   *head;
    t_packet_node   *tail;
    pthread_mutex_t mutex;
    pthread_cond_t  cond;
} t_packet_queue;

extern t_packet_queue g_packet_queue;

struct pseudo_header
{
    uint32_t    src_addr;
    uint32_t    dst_addr;
    uint8_t     zero;
    uint8_t     protocol;
    uint16_t    tcp_length;
};

typedef enum e_opcode
{
    LOCK,
    UNLOCK,
    INIT,
	DESTROY,
	CREATE,
	JOIN,
	DETACH
}   t_opcode;

typedef enum e_scan_flags
{
    SCAN_SYN    = 1 << 0,
    SCAN_NULL   = 1 << 1,
    SCAN_FIN    = 1 << 2,
    SCAN_XMAS   = 1 << 3,
    SCAN_ACK    = 1 << 4,
    SCAN_UDP    = 1 << 5
}   t_scan_flags;

typedef enum e_port_state
{
    PORT_UNKNOWN,
    PORT_OPEN,
    PORT_CLOSED,
    PORT_FILTERED,
    PORT_UNFILTERED,
    PORT_OPEN_FILTERED
}   t_port_state;

struct ping_packet
{
    struct icmphdr          icmp_hdr;
    struct timeval          timestamp;
    char                    data[ICMP_PAYLOAD_SIZE];
};

typedef struct s_port
{
    int                     number;
    int                     start_port;
    int                     end_port;
    t_port_state            state;
}   t_port;

typedef struct s_config
{
    /* User Options */
    bool                    show_help;
    bool                    use_file;
    char                    *hostname;
    char                    *file_input;
    int                     argc;
    int                     ttl;
    struct  in_addr         ip_address;

    /* Scan Options */
    int                     scan_type;

    /* Ports */
    int                     ports_tokens;
    int                     port_bitmap[65536];
    int                     total_ports;
    t_port                  *ports;

    /* Threading */
    long                    nprocs;
    int                     speedup;
    pthread_t               *threads;
    int                     next_port_idx; 

    /* Mutexes */
    t_mutex                 work_mutex;         // Para tomar puertos
    t_mutex                 print_mutex;        // Para imprimir
    t_mutex                 send_mutex;         // Para sendto() en raw socket
    t_mutex                 recv_mutex;         // Para recvfrom() en raw socket

    /* Runtime */
    bool                    is_valid;
    int                     sockfd;
    pcap_t                  *pcap_handle;
    int                     pcap_datalink;
    uint32_t                local_ip;
    char                    interface[16];
}   t_config;

typedef struct s_thread_context
{
    int                     thread_id;
    int                     *next_port_idx;
    t_mutex                 *work_mutex; 
    t_mutex                 *print_mutex; 
    t_mutex                 *send_mutex; 
    t_mutex                 *recv_mutex; 
    unsigned char           sendbuffer[MAX_PACKET_SIZE];
    unsigned char           recvbuffer[MAX_PACKET_SIZE];
    struct sockaddr_in      target_addr;
    struct ping_packet      packets[MAX_PACKET_SIZE];
    t_config                *conf;
    uint32_t                last_seq_sent;
    pcap_t                  *pcap_handle;
}   t_thread_context;

//*** Init Functions ***/

int         main(int argc, char **argv);
void        cleanup(t_config *conf, t_thread_context *threads);
void        free_packet_queue(void);

//*** Parser ***/

void        init_struct(t_config *conf, int argc);
int         ft_parser_args(t_config *conf, char **argv);
int         parse_ip(t_config *conf, char **argv, int i);
int         parse_ports(t_config *conf, char **argv, int i);
int         port_validator(t_config *conf, char **token);
int         validate_range(const char *token, int *start, int *end);
int         parse_speedup(t_config *conf, char **argv, int i);
int         parse_scantypes(t_config *conf, char **argv, int i);
int         parse_file(t_config *conf, char **argv, int i);
char        **split_scan(char *str, char c);
uint32_t    get_local_ip(void);

/*** Socket & DNS ***/

int         dns_resolution(t_config *conf);
int         socket_creation(t_config *conf);
int         icmp_creation(t_thread_context *ctx, int port);
uint16_t    calculate_checksum(void *packet, size_t len);
int         send_socket(t_thread_context *ctx, int port, int idx);
int         receive_response(t_thread_context *ctx, int port);
int         process_tcp_response(t_thread_context *ctx, const u_char *packet, struct pcap_pkthdr *header, int port);
void        set_port_state(t_config *conf, int port, t_port_state state);
int         get_packet_for_thread(t_thread_context *ctx, const u_char **packet, struct pcap_pkthdr **header);
void        *packet_reader_thread(void *arg);

//*** Show Printouts***/

void        show_help(t_config *conf, t_thread_context *threads);
void        show_configuration(t_config *conf);
char        *show_scantype(t_config *conf);

//** Signals **/

void        init_signal(void);
void        handler_singint(int signum);

/*** Utils Functions ***/

char        **split_tokens(char *str, t_config *conf);
int         count_tokens(char *str);
char        *ft_strndup(char *str, int num);
void        double_free(char **ports);
int         find_dash(char *str);
char	    *ft_substr(char *str, int start, int len);
int         ft_strlen(char *str);
int         ft_atoi_dav(char *str, int *limit);

/*** Threads ***/

void        threads_creation(t_config *conf, t_thread_context *ctx_array);
void	    *thread_routine(void *data);
void        ft_mutex(t_mutex *mutex, t_opcode opcode);
void        ft_threads(t_thread_context *thread, void *(*foo)(void *), void *data, t_opcode opcode);
int         sequential_scan(t_config *conf);
void        notify_threads_stop(void);

/*** Scan Ports ***/

int         scan_port(t_thread_context *ctx, int port);
int         analysis_flags(t_thread_context *ctx, int port);
int         scan_now(t_thread_context *ctx, int port);
int         init_scan(t_thread_context *ctx, int port);
void        set_port_state(t_config *conf, int port, t_port_state state);
int         set_default_ports(t_config *conf, t_thread_context *threads);

/*** SYN SCAN ***/

int         packet_build(t_thread_context *ctx, int port);
int         packet_build(t_thread_context *ctx, int port);
int         send_packet(t_thread_context *ctx, int port);
int         receive_response(t_thread_context *ctx, int port);
int         offset_calculate(t_thread_context *ctx);

#endif 