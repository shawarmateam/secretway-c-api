#include <iostream>
#include "secretway-api.h"

using namespace std;

// CODE FOR TESTS
int main(int argc, char* argv[])
{
    UserConf u_cfg = swParseConfig();
    std::vector<DbIp> db_ips = swParseIpList("server-list.conf");

    DbIp first_ip = db_ips.at(0);

    cout << first_ip.ip << endl;
    cout << first_ip.port << endl;
    
    swLoadKeys(&u_cfg, "public_key.pem", "private_key.pem");
    swLoadServerKey(&first_ip, "private_srvr_key.pem");

    int status_msg = swSendMsg("test", "0", &u_cfg, &first_ip);
    if (status_msg) return 1;

    printf("id: '%s'\n", u_cfg.id);
    printf("pswd: '%s'\n", u_cfg.password);

    if (argc == 2) {
        std::string test = swDecryptMsg((void *) first_ip.private_key, argv[1]);
        cout << "MSG: " << test << endl;
    }

    // Remove mem
    free(u_cfg.id);
    free(u_cfg.password);
    freeDbIpVector(db_ips);

    return 0;
}
