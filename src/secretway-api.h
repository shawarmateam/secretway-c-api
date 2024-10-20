#ifndef SECRETWAY_API_H
#define SECRETWAY_API_H

char* swReadGolang(const char* fp, const char** args);
int swSendMsg(const int PORT, const char* SERVER_IP, char* message, int user_id, char* password, int s_ui);
void swTest();

#endif // SECRETWAY_API_H
