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

    struct UserConf* u_cfg = swGetConf(args_yk, "./src-golang/yaml-parser");

    for (int i=0; u_cfg->db_ips[i] != NULL; ++i) {
        printf("db_ips: '%s'\n", u_cfg->db_ips[i]);
    }

    printf("id: '%s'\n", u_cfg->id);
    printf("pswd: '%s'\n", u_cfg->password);
    printf("pr_key: '%s'\n", u_cfg->private_key);
    printf("pu_key: '%s'\n", u_cfg->public_key);

    return 0;
}
