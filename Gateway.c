// Client side implementation of UDP client-server model
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define PORT     8080
#define MAXLINE 1024


//TODO גתיבה על חלק א
//TODO גתיבה על חלק ב
//TODO גתיבה על חלק ג
//TODO גתיבה על חלק ד




int main(int argc, char *argv[]) {
    //getting host from user
    if(argc != 2){
        printf("error format ./Gateway <host>.\n");
        return -1;
    }
    int sockFromGateway;
    int sockToGateway;
    struct sockaddr_in fromGatewayaddr, cliaddr;
    char buffer[MAXLINE];
    struct sockaddr_in toGatewayAddr;

    // Creating socket
    if ((sockFromGateway = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }
    printf("[+] created socket with host\n");
    memset(&fromGatewayaddr, 0, sizeof(fromGatewayaddr));

    // Filling fromGateway information
    fromGatewayaddr.sin_family = AF_INET;
    fromGatewayaddr.sin_port = htons(PORT + 1);
    fromGatewayaddr.sin_addr.s_addr = inet_addr(argv[1]);


  //creating socket
    if ((sockToGateway = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }
    printf("[+] created socket client\n");

    memset(&toGatewayAddr, 0, sizeof(toGatewayAddr));
    memset(&cliaddr, 0, sizeof(cliaddr));

    // Filling fromGateway information
    toGatewayAddr.sin_family = AF_INET; // IPv4
    toGatewayAddr.sin_addr.s_addr = INADDR_ANY;
    toGatewayAddr.sin_port = htons(PORT);

    // Bind the socket with the fromGateway address
    if (bind(sockToGateway, (const struct sockaddr *) &toGatewayAddr,
             sizeof(toGatewayAddr)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    printf("[+] bind socket client\n");

    int len, n;
    len = sizeof(cliaddr);
    while (1) {
        //receiving from "toGateway"
        bzero(buffer, MAXLINE);
        n = recvfrom(sockToGateway, (char *) buffer, MAXLINE,
                     MSG_WAITALL, (struct sockaddr *) &cliaddr,
                     &len);
        buffer[n] = '\0';
        printf("client : %s\n", buffer);

        //toss coin to your witcher
        int toThrow = ((float) random()) / ((float) RAND_MAX) < 0.5;

        if (toThrow) {
            printf("[-] Massage throned\n");
            continue;
        }
        //pass to "fromGateway"
        sendto(sockFromGateway, (char *) buffer, MAXLINE,
               MSG_CONFIRM, (const struct sockaddr *) &fromGatewayaddr,
               sizeof(fromGatewayaddr));
        printf("[+] Message pass to host.\n");
    }


    close(sockFromGateway);
    return 0;
}
