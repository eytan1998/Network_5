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
int main() {
    int sockToGateway;
    struct sockaddr_in gateaddr;

    // Creating socket file descriptor
    if ((sockToGateway = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }
    printf("[+] created socket toGateway\n");

    memset(&gateaddr, 0, sizeof(gateaddr));
    // Filling server information
    gateaddr.sin_family = AF_INET;
    gateaddr.sin_port = htons(PORT);
    gateaddr.sin_addr.s_addr = INADDR_ANY;

    for (int i = 0; i < 10; ++i) {
        char hello[32];
        sprintf(hello, "Please pass this massage#%d", i);

        sendto(sockToGateway, (const char *) hello, strlen(hello),
               MSG_CONFIRM, (const struct sockaddr *) &gateaddr,
               sizeof(gateaddr));
        printf("Message sent to gateway: %s\n", hello);
    }
    close(sockToGateway);
    return 0;
}
