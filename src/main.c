#include <stdio.h>
#include "secretway-api.h"
// FILE FOR TESTS

int main() {
    //swConnect(1201, "127.0.0.1", "{msg:\"hello from C!\", userId:\"0\", password:\"hui_penis\", sendUserId:0, client:true}\n");

    char* args_arr[] = {
        "-msg",
        "\"hello from go & c!\"",
        "-id",
        "0",
        "-pw",
        "hui_penis",
        "-sui",
        "0",
        NULL
    };

    const char** args = (const char**)args_arr;
    
    char* output = swReadGolang("./src-golang/json-parser", args);
    printf(output);printf("\n");

    return 0;
}
