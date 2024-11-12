#include <iostream>
#include "secretway-api.h"

using namespace std;

int main(int argc, char* argv[])
{
    UserConf u_cfg = swParseConfig();
    UserConf server_test;
    std::vector<DbIp> db_ips = swParseIpList("server-list.conf");

    DbIp first_ip = db_ips.at(0);

    cout << first_ip.ip << endl;
    cout << first_ip.port << endl;
    
    swLoadKeys(&u_cfg, "public_key.pem", "private_key.pem");
    swLoadKeys(&server_test, "public_key.pem", "private_srvr_key.pem");
    int status_msg = swSendMsg("test", "0", &u_cfg, &first_ip);

    printf("id: '%s'\n", u_cfg.id);
    printf("pswd: '%s'\n", u_cfg.password);

    if (argc == 2) {
        std::string test = swDecryptMsg((void *) server_test.private_key, argv[1]);
    }

    // Remove mem
    free(u_cfg.id);
    free(u_cfg.password);
    freeDbIpVector(db_ips);

    return 0;
}
