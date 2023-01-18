


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

#define SIZE_ETHERNET 14


/* IP header */
struct ipheader {
    u_char ip_vhl;                 /* version << 4 | header length >> 2 */
    u_char ip_tos;                 /* type of service */
    u_short ip_len;                 /* total length */
    u_short ip_id;                  /* identification */
    u_short ip_off;                 /* fragment offset field */
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
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
    u_short th_win;                 /* window */
    u_short th_sum;                 /* checksum */
    u_short th_urp;                 /* urgent pointer */
};
struct payloadhead {
    uint32_t unixtime;
    uint16_t length;
    uint16_t flags;
#define CACHE 0x1000
#define STEPS 0x800
#define TYPE 0x400
#define STATUS 0x3FF
    uint16_t cache;
    uint16_t padding;
};


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    /* declare pointers to packet headers */
    struct ipheader *ip = NULL;/* The IP header */
    struct tcpheader *tcp = NULL;        /* The TCP header */
    struct payloadhead *payload = NULL; /* The Payload header */


    //set up all pointers
    ip = (struct ipheader *) (packet + SIZE_ETHERNET);
    int size_ip = IP_HL(ip) * 4;
    tcp = (struct tcpheader *) (packet + SIZE_ETHERNET + size_ip);
    int size_tcp = TH_OFF(tcp) * 4;
    payload = (struct payloadhead *) (packet + SIZE_ETHERNET + size_ip + size_tcp);
    u_char *data = (u_char *) (packet + SIZE_ETHERNET + size_ip + size_tcp + sizeof(struct payloadhead));
    size_t len = header->len - (SIZE_ETHERNET + size_ip + size_tcp);

    //print sniffed packet
    FILE *fps = fopen("209216381_206563215.txt", "a");
    static int x = 1;
    printf("Got packet #%d\n", x);
    fprintf(fps, "############################-%d-#################################\n", x++);
    fprintf(fps, "#######################=---HEADER----=##########################\n");
    fprintf(fps, "################################################################\n");
    fprintf(fps, "[#] source_ip: %s.\n", inet_ntoa(ip->ip_src));
    fprintf(fps, "[#] dest_ip: %s.\n", inet_ntoa(ip->ip_dst));
    fprintf(fps, "[#] source_port: %d.\n", ntohs(tcp->th_sport));
    fprintf(fps, "[#] dest_port: %d.\n", ntohs(tcp->th_dport));
    if(header->len >  SIZE_ETHERNET + size_ip + size_tcp) { // more info after tcp header
        fprintf(fps, "[#] timestamp: %u.\n", ntohl(payload->unixtime));
        fprintf(fps, "[#] total_length: %hu.\n", ntohs(payload->length));
        fprintf(fps, "[#] cache_flag: %d.\n", (ntohs(payload->flags) & CACHE) >> 12); //bitwize operations
        fprintf(fps, "[#] steps_flag: %d.\n", (ntohs(payload->flags) & STEPS) >> 11);
        fprintf(fps, "[#] type_flag: %d.\n", (ntohs(payload->flags) & TYPE) >> 10);
        fprintf(fps, "[#] status_code: %d.\n", (ntohs(payload->flags) & STATUS));
        fprintf(fps, "[#] cache_control: %hu.\n", ntohs(payload->cache));

        //only print if there is data
        if (len > 0) {
            fprintf(fps, "\n################################################################\n");
            fprintf(fps, "#######################=---DATA----=#########################\n");
            fprintf(fps, "################################################################\n ");
            int i;
            //-12 account for payload header
            //+1 for devide by 16 not on first time
            for (i = 1; i < len + 1 - 12; i++) {
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
    }

    fprintf(fps, "\n");

    fflush(fps);
    free(fps);


}


int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("error format ./Sniffer <device>.\n");
        return -1;
    }
    char *dev = argv[1];   /* capture device name */
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
    printf("[+] start sniffing on %s\n", dev);

    /* now we can set our callback function */
    pcap_loop(handle, -1, got_packet, NULL);

    /* cleanup */
    pcap_freecode(&fp);
    pcap_close(handle);

    return 0;
}