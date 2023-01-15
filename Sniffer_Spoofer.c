


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


    /*********************************************************
      Step 1: Fill in the ICMP header.
    ********************************************************/
    struct icmpheader *icmp = (struct icmpheader *)
            (packet  +SIZE_ETHERNET + sizeof(struct ipheader));
    if(icmp->icmp_type != 8) return;
    icmp->icmp_type = 0; //ICMP Type: 8 is request, 0 is reply.
    icmp->icmp_seq = htons(icmp->icmp_seq+1);
    // Calculate the checksum for integrity
    icmp->icmp_chksum = 0;
    icmp->icmp_chksum = in_cksum((unsigned short *) icmp,
                                 sizeof(struct icmpheader));

    /*********************************************************
       Step 2: Fill in the IP header.
     ********************************************************/

    struct ipheader *ip = (struct ipheader *) (packet + SIZE_ETHERNET);

    ip->iph_ver = 4;
    ip->iph_ihl = 5;
    ip->iph_ttl = 20;
    char* addr = inet_ntoa(ip->iph_destip);
    ip->iph_destip.s_addr = inet_addr(inet_ntoa(ip->iph_sourceip));
    ip->iph_sourceip.s_addr = inet_addr(addr);
    ip->iph_protocol = IPPROTO_ICMP;
    ip->iph_len = htons(sizeof(struct ipheader) +
                        sizeof(struct icmpheader));
    /*********************************************************
       Step 3: Finally, send the spoofed packet
     ********************************************************/
    send_raw_ip_packet(ip);

}


int main() {
    char *dev = "wlp0s20f3";   /* capture device name */
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

    /* now we can set our callback function */
    pcap_loop(handle, -1, got_packet, NULL);

    /* cleanup */
    pcap_freecode(&fp);
    pcap_close(handle);


    return 0;
}