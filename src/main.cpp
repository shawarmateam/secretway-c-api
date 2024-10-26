#include <iostream>
#include "secretway-api.h"

using namespace std;

int main()
{
    UserConf *u_cfg = swParseConfig();
    //u_cfg->id = "0";
    //u_cfg->password = "hui_penis";
    printf("id: '%s'\n", u_cfg->id);
    printf("pswd: '%s'\n", u_cfg->password);

    //swSendMsg("hello \\w parser", "0", u_cfg);
    return 0;
}
