#include <iostream>
#include "secretway-api.h"

using namespace std;

int main()
{
    UserConf *u_cfg = swParseConfig();

    swSendMsg("test", "0", u_cfg);
    printf("id: '%s'\n", u_cfg->id);
    printf("pswd: '%s'\n", u_cfg->password);

    return 0;
}
