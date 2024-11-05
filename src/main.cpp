#include <iostream>
#include "secretway-api.h"

using namespace std;

int main()
{
    UserConf u_cfg = swParseConfig();
    std::vector<DbIp> db_ips = swParseIpList("server-list.conf");

    DbIp first_ip = db_ips.at(0);

    cout << first_ip.ip << endl;
    cout << first_ip.port << endl;
    
    swLoadKeys(&u_cfg, "public_key.pem", "private_key.pem");
    int status_msg = swSendMsg("test", "0", &u_cfg, &first_ip);

    printf("id: '%s'\n", u_cfg.id);
    printf("pswd: '%s'\n", u_cfg.password);

    // Remove mem
    free(u_cfg.id);
    free(u_cfg.password);
    freeDbIpVector(db_ips);

    return 0;
}
