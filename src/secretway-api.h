#ifndef SECRETWAY_API_H
#define SECRETWAY_API_H
#include <vector>

struct DbIp {
    short port;
    char* ip;
};

struct UserConf
{
    char* id;
    char* password;
    const char* private_key;
    const char* public_key;
    const bool client = true;
};

UserConf swParseConfig();
int swSendMsg(const char* msg, const char* s_ui, UserConf *u_cfg, DbIp* db_ip);
std::vector<DbIp> swParseIpList(const std::string &filename);
void freeDbIpVector(std::vector<DbIp>& db_ips);

#endif // SECRETWAY_API_H
