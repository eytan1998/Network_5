


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
#include <unistd.h>

#define ETHER_ADDR_LEN 6
/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14


/* Ethernet header */
struct ethheader {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* source host address */
    u_short ether_type;                  /* IP? ARP? RARP? etc */
};


/* ICMP Header  */
struct icmpheader {
    unsigned char icmp_type; // ICMP message type
    unsigned char icmp_code; // Error code
    unsigned short int icmp_chksum; //Checksum for ICMP Header and data
    unsigned short int icmp_id;     //Used for identifying request
    unsigned short int icmp_seq;    //Sequence number
};
/* IP Header */
struct ipheader {
    unsigned char iph_ihl: 4, //IP header length
    iph_ver: 4; //IP version
    unsigned char iph_tos; //Type of service
    unsigned short int iph_len; //IP Packet length (data + header)
    unsigned short int iph_ident; //Identification
    unsigned short int iph_flag: 3, //Fragmentation flags
    iph_offset: 13; //Flags offset
    unsigned char iph_ttl; //Time to Live
    unsigned char iph_protocol; //Protocol type
    unsigned short int iph_chksum; //IP datagram checksum
    struct in_addr iph_sourceip; //Source IP address
    struct in_addr iph_destip;   //Destination IP address
};


unsigned short in_cksum(unsigned short *buf, int length) {
    unsigned short *w = buf;
    int nleft = length;
    int sum = 0;
    unsigned short temp = 0;


/**
     * The algorithm uses a 32 bit accumulator (sum), adds
     * sequential 16 bit words to it, and at the end, folds back all
     * the carry bits from the top 16 bits into the lower 16 bits.
     */

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }


/* treat the odd byte at the end, if any */

    if (nleft == 1) {
        *(u_char *) (&temp) = *(u_char *) w;
        sum += temp;
    }


    sum = (sum >> 16) + (sum & 0xffff);  // add hi 16 to low 16
    sum += (sum >> 16);                  // add carry
    return (unsigned short) (~sum);
}

/*************************************************************
  Given an IP packet, send it out using a raw socket.
**************************************************************/

void send_raw_ip_packet(struct ipheader *ip) {
    struct sockaddr_in dest_info;
    int enable = 1;

    // Step 1: Create a raw network socket.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    // Step 2: Set socket option.
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL,
               &enable, sizeof(enable));

    // Step 3: Provide needed information about destination.
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;

    // Step 4: Send the packet out.
    sendto(sock, ip, ntohs(ip->iph_len), 0,
           (struct sockaddr *) &dest_info, sizeof(dest_info));
    close(sock);
}


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    char buffer[1500];
    memset(buffer, 0, 1500);

    //spoofed and sniffed icmp
    struct icmpheader *spoofed_icmp = (struct icmpheader *)
            (packet + sizeof(struct ipheader)+ SIZE_ETHERNET);
    struct icmpheader *icmp = (struct icmpheader *)
            (buffer + sizeof(struct ipheader));

    if (spoofed_icmp->icmp_type != 8) return; // only the requests

    char *data = buffer + sizeof(struct ipheader) +
                 sizeof(struct icmpheader);
    const char *msg = "I am not Pong XD\n";
    int data_len = strlen(msg);
    strncpy(data, msg, data_len);


    icmp->icmp_type = 0; //set to reply
    icmp->icmp_seq = spoofed_icmp->icmp_seq;
    icmp->icmp_id = spoofed_icmp->icmp_id;
    // Calculate the checksum for integrity
    icmp->icmp_chksum = 0;
    icmp->icmp_chksum = in_cksum((unsigned short *) icmp,
                                 sizeof(struct icmpheader));
    //fill ip header
    struct ipheader *snoofed_ip = (struct ipheader *) (packet + SIZE_ETHERNET);
    struct ipheader *ip = (struct ipheader *) buffer;
    ip->iph_ver = 4;
    ip->iph_ihl = 5;
    ip->iph_ttl = 99;
    //switch the address
    ip->iph_sourceip.s_addr = snoofed_ip->iph_destip.s_addr;
    ip->iph_destip.s_addr = snoofed_ip->iph_sourceip.s_addr;
    ip->iph_protocol = IPPROTO_ICMP;
    ip->iph_len = htons(sizeof(struct ipheader) +
                        sizeof(struct icmpheader)+ data_len);


    //print
    char source[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &snoofed_ip->iph_sourceip, source, INET_ADDRSTRLEN);
    char dest[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &snoofed_ip->iph_destip, dest, INET_ADDRSTRLEN);
    static int x = 1;
    printf("Got icmp request #%d from %s -> %s\n", x++,source, dest);
    printf("Sending reply to %s\n",source);


    send_raw_ip_packet(ip);

}


int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("error format ./Sniffer_Spoofer <device>.\n");
        return -1;
    }
    char *dev = argv[1];   /* capture device name */
    char errbuf[PCAP_ERRBUF_SIZE];  /* error buffer */
    pcap_t *handle;    /* packet capture handle */

    char filter_exp[] = "icmp";  /* filter expression */
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
    printf("[+] start sniffing on %s\n",dev);

    /* now we can set our callback function */
    pcap_loop(handle, -1, got_packet, NULL);

    /* cleanup */
    pcap_freecode(&fp);
    pcap_close(handle);


    return 0;
}