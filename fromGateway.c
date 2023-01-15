// Server side implementation of UDP client-server model
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define PORT     8081
#define MAXLINE 1024

// Driver code
int main() {
    int sockFromGateway;
    char buffer[MAXLINE];
    struct sockaddr_in servaddr, cliaddr;

    // Creating socket file descriptor
    if ((sockFromGateway = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }
    printf("[+] Create socket Gateway\n");

    memset(&servaddr, 0, sizeof(servaddr));
    memset(&cliaddr, 0, sizeof(cliaddr));

    // Filling server information
    servaddr.sin_family = AF_INET; // IPv4
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(PORT);

    // Bind the socket with the server address
    if (bind(sockFromGateway, (const struct sockaddr *) &servaddr,
             sizeof(servaddr)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    printf("[+] bind socket Gateway\n");

    int len, n;

    len = sizeof(cliaddr); //len is value/result
    while (1) {
        n = recvfrom(sockFromGateway, (char *) buffer, MAXLINE,
                     MSG_WAITALL, (struct sockaddr *) &cliaddr,
                     &len);
        buffer[n] = '\0';
        printf("Massage come from Gateway : %s\n", buffer);

    }
    return 0;
}
