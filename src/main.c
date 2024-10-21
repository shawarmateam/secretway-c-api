#include <stdio.h>
#include "secretway-api.h"
// FILE FOR TESTS

int main() {
    //swSendMsg(1201, "127.0.0.1", "hello from C SecretWay API!", 0, "hui_penis", 0);

    char* args[] = {
        "-c",
        "./src-golang/config.yaml",
        NULL
    };
    const char** args_yk = (const char**)&args;

    char** test = swGetConf(args_yk, "./src-golang/yaml-parser");

    return 0;
}
