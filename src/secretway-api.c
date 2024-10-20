#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "secretway-api.h"

//#define PORT 8080
//#define SERVER_IP "127.0.0.1"

int swConnect(const int PORT, const char* SERVER_IP, char* message) {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[1024] = {0};

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\nSocket creation error\n");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // char* ip -> binary ip
    if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) {
        printf("\nInvalid address / Address not supported\n");
        return -2;
    }


    if (connect(sock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
        printf("\nConnection Failed\n");
        return -3;
    }

    // Send package to server
    send(sock, message, strlen(message), 0);
    printf("Message sent\n");

    // Get package from server
    int valread = read(sock, buffer, 1024);
    printf("%s\n", buffer);

    // Close
    close(sock);
    return 0;
}

void swTest() {
    printf("hello world\n");
}
