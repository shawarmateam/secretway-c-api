#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "secretway-api.h"
#include <string.h>

#define BUFFER_SIZE 128

/*struct UserConf {
    char* id;
    char* password;
    char* private_key;
    char* public_key;
    
    char** db_ips;
};*/

char* swReadGolang(const char* fp, const char** args) {
    printf("LOG: in swReadGolang()\n");

    char command[256];
    snprintf(command, sizeof(command), "%s", fp);

    // Adding args to exec file
    for (int i = 0; args[i] != NULL; i++) {
        strncat(command, " ", sizeof(command) - strlen(command) - 1);
        strncat(command, args[i], sizeof(command) - strlen(command) - 1);
    }

    printf(command);printf("\n");

    // Opening process
    FILE* file = popen(command, "r");

    // Reading output of program
    char buffer[BUFFER_SIZE];
    char* output = malloc(BUFFER_SIZE);

    output[0] = '\0'; // Init string

    while (fgets(buffer, sizeof(buffer), file) != NULL) {
        strncat(output, buffer, BUFFER_SIZE - strlen(output) - 1);
    }

    // Close process
    pclose(file);

    return output;
}

struct UserConf* swGetConf(const char** args, const char* parser_p) {
    char* cfg_str = swReadGolang(parser_p, args);

    char* lines[10];
    char buffer[123];
    short line_count = 0;

    strncpy(buffer, cfg_str, sizeof(buffer));
    buffer[sizeof(buffer) - 1] = '\0';

    char* line = strtok(buffer, "\n");
    while (line != NULL && line_count < 10) { // read config
        lines[line_count++] = line;
        line = strtok(NULL, "\n");
    }

    for (int i = 0; i < line_count; i++) {
        printf("Line %d: %s\n", i, lines[i]);
    }

    line_count = 0; // db_ips read sector
    char** db_ips = (char**)malloc(10 * sizeof( char* ));
    struct UserConf* u_cfg = (struct UserConf*)malloc(sizeof(struct UserConf));

    printf("LOG: start of db_ips sector\n");
    while (strcmp(lines[line_count], ".") != 0) {
        printf("LOG: line == '%s'\n", lines[line_count]);

        db_ips[line_count] = (char*)malloc(21 * sizeof(char)); // 21 is max for IPv4. example: 255.255.255:65535

        printf("LOG: '%s', '%s'\n", lines[line_count], db_ips[line_count]);
        strcpy(db_ips[line_count], lines[line_count]);
        line_count++;
    }

    printf("LOG: line_count == %d", line_count);
    db_ips[line_count] = NULL;

    printf("LOG: end of db_ips sector (%s)\n", db_ips[line_count]);

    line_count++; // read id sector
    char* id = strdup(lines[line_count]);
    printf("LOG: %d line == '%s'\n", line_count, id);

    line_count++; // read password sector
    char* password = strdup(lines[line_count]); // TODO: пофиксить ошибку неправильного заполнения

    line_count++; // read pr. key
    char* private_key = strdup(lines[line_count]);

    line_count++; // read pu. key
    char* public_key = strdup(lines[line_count]);

    // write all to struct
    printf("LOG: writing all to struct...\n");
    u_cfg->db_ips = db_ips;
    printf("LOG: db_ips: '%s', '%s'\n", db_ips[line_count], u_cfg->db_ips[line_count]);
    u_cfg->id = id;
    u_cfg->password = password;
    u_cfg->private_key = private_key;
    u_cfg->public_key = public_key;
    printf("LOG: next is return.\n");

    return u_cfg;
}

char** swGenArgs(char* message, int user_id, char* password, int s_ui) {
    printf("LOG: in swGenArgs()\n");

    // Create buffer
    char** args_arr = malloc(9 * sizeof(char*));

    // Setting up buffer
    
    args_arr[0] = "-msg";

    args_arr[1] = malloc(strlen(message) + 3);
    sprintf(args_arr[1], "\"%s\"", message);   // arg0 == msg
    printf("LOG: on //arg0 == msg\n");

    args_arr[2] = "-id";

    args_arr[3] = malloc(12);
    sprintf(args_arr[3], "%d", user_id);       // arg1 == user_id
    printf("LOG: on // arg1 == user_id\n");

    args_arr[4] = "-pw";

    args_arr[5] = malloc(strlen(password) + 3);
    sprintf(args_arr[5], "\"%s\"", password);  // arg2 == password
    printf("LOG: on // arg2 == password\n");

    args_arr[6] = "-sui";

    args_arr[7] = malloc(12);
    sprintf(args_arr[7], "%d", s_ui);          // arg3 == sendUserId
    printf("LOG: arg3 == sendUserId\n");

    args_arr[8] = NULL;

    // return
    return args_arr;
}

int swSendMsg(const int PORT, const char* SERVER_IP, char* message, int user_id, char* password, int s_ui) {
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

    // Gen package
    printf("LOG: gen package\n");
    const char** args = (const char**)swGenArgs(message, user_id, password, s_ui);
    char* package = swReadGolang("./src-golang/json-parser", args);

    free(args);

    // Send package to server
    send(sock, package, strlen(package), 0);

    printf("LOG: '");printf(package);printf("'\n\n");
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
