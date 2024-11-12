#ifndef SECRETWAY_API_H
#define SECRETWAY_API_H

#include <vector> // includes
#include <string>

struct DbIp {
    short port;
    char* ip;
};

struct UserConf
{
    char* id;
    char* password;
    void* private_key; // RSA*
    void* public_key;  // RSA*
    const bool client = true;
};

struct MsgCyph
{
    std::string cyph_msg;
    std::string salt;
};

UserConf swParseConfig();
int swSendMsg(const char* msg, const char* s_ui, UserConf *u_cfg, DbIp* db_ip);
std::vector<DbIp> swParseIpList(const std::string &filename);
void freeDbIpVector(std::vector<DbIp>& db_ips);
std::string swGenSalt();
std::string swCypherMsg(std::string package, void* pub_key, std::string salt);
void swLoadKeys(UserConf *u_cfg, std::string pu_key, std::string pr_key);
int swGenKeys(char *pu_key, char *pr_key);
std::string swDecryptMsg(void *pri_key, std::string e_msg);

#endif // SECRETWAY_API_H
