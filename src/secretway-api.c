#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "secretway-api.h"

#define BUFFER_SIZE 128
//#define PORT 8080
//#define SERVER_IP "127.0.0.1"

char* swReadGolang(const char* fp, const char** args) {
    char command[256];
    snprintf(command, sizeof(command), "%s", fp);

    // Adding args to exec file
    for (int i = 0; args[i] != NULL; i++) {
        strncat(command, " ", sizeof(command) - strlen(command) - 1);
        strncat(command, args[i], sizeof(command) - strlen(command) - 1);
    }

    // Opening process
    FILE* file = popen(command, "r");
    if (file == NULL) {
        perror("popen failed");
        return NULL;
    }

    // Reading output of program
    char buffer[BUFFER_SIZE];
    char* output = malloc(BUFFER_SIZE);
    if (output == NULL) {
        perror("malloc failed");
        pclose(file);
        return NULL;
    }
    output[0] = '\0'; // Init string

    while (fgets(buffer, sizeof(buffer), file) != NULL) {
        strncat(output, buffer, BUFFER_SIZE - strlen(output) - 1);
    }

    // Close process
    if (pclose(file) == -1) {
        perror("pclose failed");
        free(output);
        return NULL;
    }

    return output;
}

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
