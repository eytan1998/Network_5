// Client side implementation of UDP client-server model
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define PORT     8080
#define MAXLINE 1024

// Driver code
int main(int argc, char *argv[]) {
    if(argc != 2){
        printf("error format ./Gateway <host>.\n");
        return -1;
    }
    int sockFromGateway;
    char buffer[MAXLINE];
    char *hello = "Hello from client";
    struct sockaddr_in fromGatewayAddr;

    // Creating socket file descriptor
    if ((sockFromGateway = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }
    printf("[+] created socket with host\n");
    memset(&fromGatewayAddr, 0, sizeof(fromGatewayAddr));

    // Filling server information
    fromGatewayAddr.sin_family = AF_INET;
    fromGatewayAddr.sin_port = htons(PORT + 1);
    fromGatewayAddr.sin_addr.s_addr = inet_addr(argv[1]);


    int sockToGateway;
    struct sockaddr_in servaddr, cliaddr;

    // Creating socket file descriptor
    if ((sockToGateway = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }
    printf("[+] created socket client\n");

    memset(&servaddr, 0, sizeof(servaddr));
    memset(&cliaddr, 0, sizeof(cliaddr));

    // Filling server information
    servaddr.sin_family = AF_INET; // IPv4
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(PORT);

    // Bind the socket with the server address
    if (bind(sockToGateway, (const struct sockaddr *) &servaddr,
             sizeof(servaddr)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    printf("[+] bind socket client\n");

    int len, n;

    len = sizeof(cliaddr); //len is value/result
    while (1) {
        bzero(buffer, MAXLINE);
        n = recvfrom(sockToGateway, (char *) buffer, MAXLINE,
                     MSG_WAITALL, (struct sockaddr *) &cliaddr,
                     &len);
        buffer[n] = '\0';
        printf("client : %s\n", buffer);

        int toThrow = ((float) random()) / ((float) RAND_MAX) < 0.5;

        if (toThrow) {
            printf("[-] Massage throned\n");
            continue;
        }

        sendto(sockFromGateway, (char *) buffer, MAXLINE,
               MSG_CONFIRM, (const struct sockaddr *) &fromGatewayAddr,
               sizeof(fromGatewayAddr));
        printf("[+] Message pass to host.\n");
    }


    close(sockFromGateway);
    return 0;
}
