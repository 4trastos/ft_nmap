#include "ft_nmap.h"

void *packet_reader_thread(void *arg)
{
    t_config *conf = (t_config *)arg;
    struct pcap_pkthdr *header;
    const u_char *packet;
    int ret;

    while (!g_stop)
    {
        ret = pcap_next_ex(conf->pcap_handle, &header, &packet);
        if (ret == 1)
        {
            t_packet_node *node = malloc(sizeof(t_packet_node));
            node->header = *header;
            node->packet = malloc(header->len);
            memcpy((void*)node->packet, packet, header->len);
            node->next = NULL;

            pthread_mutex_lock(&g_packet_queue.mutex);
            if (!g_packet_queue.tail)
                g_packet_queue.head = node;
            else
                g_packet_queue.tail->next = node;
            g_packet_queue.tail = node;
            pthread_cond_broadcast(&g_packet_queue.cond);
            pthread_mutex_unlock(&g_packet_queue.mutex);
        }
        else if (ret == -1 || ret == -2)
            break;
        else
            usleep(1000); // Puede retornar 0 por timeout y evitar busy wait
    }
    return NULL;
}