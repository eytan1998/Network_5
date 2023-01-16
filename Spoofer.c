#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <arpa/inet.h>

/* TCP header */
typedef u_int32_t tcp_seq;
struct tcpheader {
    u_int16_t th_sport;                /* source port */
    u_int16_t th_dport;                /* destination port */
    tcp_seq th_seq;                /* sequence number */
    tcp_seq th_ack;                /* acknowledgement number */
    u_int8_t th_x2: 4;                /* (unused) */
    u_int8_t th_off: 4;                /* data offset */
    u_int8_t th_flags;
#  define TH_FIN        0x01
#  define TH_SYN        0x02
#  define TH_RST        0x04
#  define TH_PUSH        0x08
#  define TH_ACK        0x10
#  define TH_URG        0x20
    u_int16_t th_win;                /* window */
    u_int16_t th_sum;                /* checksum */
    u_int16_t th_urp;                /* urgent pointer */
};

/* Psuedo TCP header */
struct pseudo_tcp {
    unsigned saddr, daddr;
    unsigned char mbz;
    unsigned char ptcl;
    unsigned short tcpl;
    struct tcpheader tcp;
    char payload[64];
};

/* UDP Header */
struct udpheader {
    u_int16_t udp_sport;           /* source port */
    u_int16_t udp_dport;           /* destination port */
    u_int16_t udp_ulen;            /* udp length */
    u_int16_t udp_sum;             /* udp checksum */
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

void fillIcmpHeader(char buffer[1500]);

void fillUdpHeader(char buffer[1500]);

void fillTcpHeader(char buffer[1500]);

unsigned short in_cksum(unsigned short *buf, int length) {
    unsigned short *w = buf;
    int nleft = length;
    int sum = 0;
    unsigned short temp = 0;

    /*
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

    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff);  // add hi 16 to low 16
    sum += (sum >> 16);                  // add carry
    return (unsigned short) (~sum);
}

unsigned short calculate_tcp_checksum(struct ipheader *ip) {
    struct tcpheader *tcp = (struct tcpheader *) ((u_char *) ip +
                                                  sizeof(struct ipheader));

    int tcp_len = ntohs(ip->iph_len) - sizeof(struct ipheader);

    /* pseudo tcp header for the checksum computation */
    struct pseudo_tcp p_tcp;
    memset(&p_tcp, 0x0, sizeof(struct pseudo_tcp));

    p_tcp.saddr = ip->iph_sourceip.s_addr;
    p_tcp.daddr = ip->iph_destip.s_addr;
    p_tcp.mbz = 0;
    p_tcp.ptcl = IPPROTO_TCP;
    p_tcp.tcpl = htons(tcp_len);
    memcpy(&p_tcp.tcp, tcp, tcp_len);

    return (unsigned short) in_cksum((unsigned short *) &p_tcp,
                                     tcp_len + 12);
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

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("error format ./Spoofer <protocol>(icmp | udp | tcp).\n");
        return -1;
    }
    printf("You chosen %s\n", argv[1]);

    char buffer[1500];
    memset(buffer, 0, 1500);
    struct ipheader *ip = (struct ipheader *) buffer;

    if (strcmp(argv[1], "icmp") == 0) {
        fillIcmpHeader(buffer);

    } else if (strcmp(argv[1], "udp") == 0) {
        fillUdpHeader(buffer);

    } else if (strcmp(argv[1], "tcp") == 0) {
        fillTcpHeader(buffer);

    } else {
        printf("[-] invalid choice\n");
        return -1;
    }

    send_raw_ip_packet(ip);
    printf("[+] spoofed %s packet\n", argv[1]);

    return 0;
}

/*************************************************************
                        fill TCP header
**************************************************************/
void fillTcpHeader(char buffer[1500]) {
    //fill TCP Header with custom massage
    struct tcpheader *tcp = (struct tcpheader *) (buffer + sizeof(struct ipheader));
    char *data = buffer + sizeof(struct ipheader) + sizeof(struct tcpheader);
    const char *msg = "I am snooped tcp package\n";
    int data_len = strlen(msg);
    strncpy(data, msg, data_len);

    tcp->th_sport = htons(56789);
    tcp->th_dport = htons(8765);
    tcp->th_off = 5;  //tcp header size
    tcp->th_flags = TH_FIN; // add fin flag
    tcp->th_win = htons(1234);
    tcp->th_sum = 0; //leave checksum 0 now, filled later by pseudo header
    tcp->th_urp = 0;

    //fill ip header
    struct ipheader *ip = (struct ipheader *) buffer;
    ip->iph_ver = 4;
    ip->iph_ihl = 5;
    ip->iph_ttl = 20;
    ip->iph_sourceip.s_addr = inet_addr("10.0.0.12");
    ip->iph_destip.s_addr = inet_addr("10.0.0.8");
    ip->iph_protocol = IPPROTO_TCP;
    ip->iph_len = htons(sizeof(struct ipheader) +
                        sizeof(struct tcpheader) + data_len);

    //filled by pseudo header
    tcp->th_sum = calculate_tcp_checksum(ip);

}
/*************************************************************
                        fill UDP header
**************************************************************/
void fillUdpHeader(char buffer[1500]) {
    //fill udp with custom massage
    struct udpheader *udp = (struct udpheader *) (buffer +
                                                  sizeof(struct ipheader));
    char *data = buffer + sizeof(struct ipheader) +
                 sizeof(struct udpheader);
    const char *msg = "I am snooped udp package\n";
    int data_len = strlen(msg);
    strncpy(data, msg, data_len);
    udp->udp_sport = htons(9999);
    udp->udp_dport = htons(9998);
    udp->udp_ulen = htons(sizeof(struct udpheader) + data_len);
    udp->udp_sum = 0;

    //fill ip
    struct ipheader *ip = (struct ipheader *) buffer;
    ip->iph_ver = 4;
    ip->iph_ihl = 5;
    ip->iph_ttl = 20;
    ip->iph_sourceip.s_addr = inet_addr("10.0.0.12");
    ip->iph_destip.s_addr = inet_addr("10.0.0.8");
    ip->iph_protocol = IPPROTO_UDP;
    ip->iph_len = htons(sizeof(struct ipheader) +
                        sizeof(struct udpheader) + data_len);

}
/*************************************************************
                        fill ICMP header
**************************************************************/
void fillIcmpHeader(char buffer[1500]) {
    //fill icmp
    struct icmpheader *icmp = (struct icmpheader *)
            (buffer + sizeof(struct ipheader));
    icmp->icmp_type = 8; //request

    // Calculate the checksum for integrity
    icmp->icmp_chksum = 0;
    icmp->icmp_chksum = in_cksum((unsigned short *) icmp,
                                 sizeof(struct icmpheader));

    //fill ip
    struct ipheader *ip = (struct ipheader *) buffer;
    ip->iph_ver = 4;
    ip->iph_ihl = 5;
    ip->iph_ttl = 20;
    ip->iph_sourceip.s_addr = inet_addr("10.0.0.8");
    ip->iph_destip.s_addr = inet_addr("10.0.0.12");
    ip->iph_protocol = IPPROTO_ICMP;
    ip->iph_len = htons(sizeof(struct ipheader) +
                        sizeof(struct icmpheader));

}
 