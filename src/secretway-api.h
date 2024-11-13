#ifndef SECRETWAY_API_H
#define SECRETWAY_API_H

// includes
#include <vector> 
#include <string>

// OffAccS IP struct
struct DbIp {
    short port;
    char* ip;
    void *private_key; // RSA*
};

// user config struct
struct UserConf
{
    char* id;
    char* password;
    void* private_key; // RSA*
    void* public_key;  // RSA*
    const bool client = true;
};

// struct of cyphered message (SW protocol)
struct MsgCyph
{
    std::string cyph_msg;
    std::string salt;
};

// parsing
UserConf swParseConfig();
std::vector<DbIp> swParseIpList(const std::string &filename);

// sending
int swSendMsg(const char* msg, const char* s_ui, UserConf *u_cfg, DbIp* db_ip);

// free
void freeDbIpVector(std::vector<DbIp>& db_ips);

// gen
std::string swGenSalt();
std::string swCypherMsg(std::string package, void* pub_key, std::string salt);
int swGenKeys(char *pu_key, char *pr_key);

// load
void swLoadKeys(UserConf *u_cfg, std::string pu_key, std::string pr_key);
void swLoadServerKey(DbIp *db_ip, std::string pu_key);

// decrypt
std::string swDecryptMsg(void *pri_key, std::string e_msg);

#endif // SECRETWAY_API_H
