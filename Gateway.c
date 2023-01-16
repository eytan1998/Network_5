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


// צילמוי מסך חלק א
// צילמוי מסך חלק ב
// צילמוי מסך חלק ג
// צילמוי מסך חלק ד

// צילומי ווירשרק חלק א
// צילומי ווירשרק חלק ב
// צילומי ווירשרק חלק ג
// צילומי ווירשרק חלק ד

//TODO הערות על הקוד


int main(int argc, char *argv[]) {
    //getting host from user
    if(argc != 2){
        printf("error format ./Gateway <host>.\n");
        return -1;
    }
    int sockFromGateway;
    char buffer[MAXLINE];
    struct sockaddr_in toGatewayAddr;

    // Creating socket
    if ((sockFromGateway = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }
    printf("[+] created socket with host\n");
    memset(&toGatewayAddr, 0, sizeof(toGatewayAddr));

    // Filling toGateway information
    toGatewayAddr.sin_family = AF_INET;
    toGatewayAddr.sin_port = htons(PORT + 1);
    toGatewayAddr.sin_addr.s_addr = inet_addr(argv[1]);


    int sockToGateway;
    struct sockaddr_in fromGatewayaddr, cliaddr;

    // Creating socket
    if ((sockToGateway = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }
    printf("[+] created socket client\n");

    memset(&fromGatewayaddr, 0, sizeof(fromGatewayaddr));
    memset(&cliaddr, 0, sizeof(cliaddr));

    // Filling fromGateway information
    fromGatewayaddr.sin_family = AF_INET; // IPv4
    fromGatewayaddr.sin_addr.s_addr = INADDR_ANY;
    fromGatewayaddr.sin_port = htons(PORT);

    // Bind the socket with the fromGateway address
    if (bind(sockToGateway, (const struct sockaddr *) &fromGatewayaddr,
             sizeof(fromGatewayaddr)) < 0) {
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
               MSG_CONFIRM, (const struct sockaddr *) &toGatewayAddr,
               sizeof(toGatewayAddr));
        printf("[+] Message pass to host.\n");
    }


    close(sockFromGateway);
    return 0;
}
