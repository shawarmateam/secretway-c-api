#ifndef SECRETWAY_API_H
#define SECRETWAY_API_H

struct UserConf
{
    char** db_ips;

    char* id;
    char* password;
    const char* private_key;
    const char* public_key;
    const bool client = true;
};

UserConf* swParseConfig();
int swSendMsg(const char* msg, const char* s_ui, UserConf *u_cfg);

#endif // SECRETWAY_API_H
