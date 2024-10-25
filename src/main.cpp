#include <iostream>
#include "secretway-api.cpp"
using namespace std;

int main()
{
    UserConf *u_cfg;
    u_cfg->id = "0";
    u_cfg->password = "hui_penis";

    swSendMsg("hello \\w parser", "0", u_cfg);
    return 0;
}
