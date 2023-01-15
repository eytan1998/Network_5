


#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define ETHER_ADDR_LEN 6
/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14


/* Ethernet header */
struct ethheader {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* source host address */
    u_short ether_type;                  /* IP? ARP? RARP? etc */
};

/* IP header */
struct ipheader {
    u_char ip_vhl;                 /* version << 4 | header length >> 2 */
    u_char ip_tos;                 /* type of service */
    u_short ip_len;                 /* total length */
    u_short ip_id;                  /* identification */
    u_short ip_off;                 /* fragment offset field */
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
    u_char ip_ttl;                 /* time to live */
    u_char ip_p;                   /* protocol */
    u_short ip_sum;                 /* checksum */
    struct in_addr ip_src, ip_dst;  /* source and dest address */
};

/* TCP header */
typedef u_int tcp_seq;

struct tcpheader {
    u_short th_sport;               /* source port */
    u_short th_dport;               /* destination port */
    tcp_seq th_seq;                 /* sequence number */
    tcp_seq th_ack;                 /* acknowledgement number */
    u_char th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;                 /* window */
    u_short th_sum;                 /* checksum */
    u_short th_urp;                 /* urgent pointer */
};
struct payloadhead {
    uint32_t unixtime;
    uint16_t length;
    uint16_t flags;
    uint16_t cache;
    uint16_t padding;
};

#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    /* declare pointers to packet headers */
    struct ipheader *ip = NULL;/* The IP header */
    struct tcpheader *tcp = NULL;        /* The TCP header */
    struct payloadhead *payload = NULL;


    ip = (struct ipheader *) (packet + SIZE_ETHERNET);
    int size_ip = IP_HL(ip) * 4;
    tcp = (struct tcpheader *) (packet + SIZE_ETHERNET + size_ip);
    int size_tcp = TH_OFF(tcp) * 4;
    payload = (struct payloadhead *) (packet + SIZE_ETHERNET + size_ip + size_tcp);
    u_char *data = (u_char *) (packet + SIZE_ETHERNET + size_ip + size_tcp + sizeof(struct payloadhead));
    size_t len = header->len - (SIZE_ETHERNET + size_ip + size_tcp);


    FILE *fps = fopen("snifferOutput.txt", "a");
    fprintf(fps, "################################################################\n");
    fprintf(fps, "#######################=---HEADER----=##########################\n");
    fprintf(fps, "################################################################\n");
    fprintf(fps, "[#] source_ip: %s.\n", inet_ntoa(ip->ip_src));
    fprintf(fps, "[#] dest_ip: %s.\n", inet_ntoa(ip->ip_dst));
    fprintf(fps, "[#] source_port: %d.\n", ntohs(tcp->th_sport));
    fprintf(fps, "[#] dest_port: %d.\n", ntohs(tcp->th_dport));
    fprintf(fps, "[#] timestamp: %u.\n", htonl(payload->unixtime));
    fprintf(fps, "[#] total_length: %u.\n", ntohs(payload->length));
    fprintf(fps, "[#] cache_flag: %d.\n", (htons(payload->flags) & 0x1000) >> 12);
    fprintf(fps, "[#] steps_flag: %d.\n", (htons(payload->flags) & 0x800) >> 11);
    fprintf(fps, "[#] type_flag: %d.\n", (htons(payload->flags) & 0x400) >> 10);
    fprintf(fps, "[#] status_code: %d.\n", (u_int16_t) (htons(payload->flags) & 0x3FF));
    fprintf(fps, "[#] cache_control: %u.\n", payload->cache);
    if (len > 0) {
        fprintf(fps, "\n################################################################\n");
        fprintf(fps, "#######################=---DATA----=#########################\n");
        fprintf(fps, "################################################################\n ");
        /* hex */

        for (int i = 1; i < len + 1 - 12; i++) {

            fprintf(fps, "%02X ", *data);
            data++;
            if (i % 16 == 0) {
                fprintf(fps, "\t");
                data -= 16;
                for (int j = 0; j < 16; ++j) {
                    if (isprint(*data))
                        fprintf(fps, "%c", *data);
                    else
                        fprintf(fps, ".");
                    data++;
                }
                fprintf(fps, "\n");
            }
            fprintf(fps, " ");
        }
    }
    fprintf(fps, "\n");

    fflush(fps);
    free(fps);

    return;

}


int main(int argc, char **argv) {
    char *dev = "lo";   /* capture device name */
    char errbuf[PCAP_ERRBUF_SIZE];  /* error buffer */
    pcap_t *handle;    /* packet capture handle */

    char filter_exp[] = "tcp";  /* filter expression */
    struct bpf_program fp;   /* compiled filter program (expression) */
    bpf_u_int32 mask;   /* subnet mask */
    bpf_u_int32 net;   /* ip */

    /* get network number and mask associated with capture device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
                dev, errbuf);
        net = 0;
        mask = 0;
    }

    /* open capture device */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    }

    /* make sure we're capturing on an Ethernet device [2] */
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "%s is not an Ethernet\n", dev);
        exit(EXIT_FAILURE);
    }

    /* compile the filter expression */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    /* apply the compiled filter */
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    /* now we can set our callback function */
    pcap_loop(handle, -1, got_packet, NULL);

    /* cleanup */
    pcap_freecode(&fp);
    pcap_close(handle);

    printf("\nCapture complete.\n");

    return 0;
}