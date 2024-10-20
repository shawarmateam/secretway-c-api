#include <stdio.h>
#include "secretway-api.h"
// FILE FOR TESTS

int main() {
    swTest();
    swConnect(1201, "127.0.0.1", "{msg:\"hello from C!\", userId:\"0\", password:\"hui_penis\", sendUserId:0, client:true}\n");
    return 0;
}
