#ifndef SECRETWAY_API_H
#define SECRETWAY_API_H

struct UserConf {
    char** db_ips;

    char* id;
    char* password;
    char* private_key;
    char* public_key;
};

char* swReadGolang(const char* fp, const char** args);
struct UserConf* swGetConf(const char** args, const char* parser_p);
int swSendMsg(const int PORT, const char* SERVER_IP, char* message, int user_id, char* password, int s_ui);
void swTest();

#endif // SECRETWAY_API_H
