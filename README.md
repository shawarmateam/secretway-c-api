# SecretWay API in C

Offical **SecretWay API** in C.
Created by [adisteyf](https://github.com/adisteyf) *(I've lost my github)*.

## How to build

1. `git clone https://github.com/shawarmateam/secretway-c-api.git`.
2. `cd secretway-c-api;chmod +x ./makeall.sh ./clrall.sh`.
3. `./makeall.sh`.

### How to clear

Run `./clrall.sh`.

## All functions at this moment

1. `char* swReadGolang(const char* fp, const char** args)` - Run golang file *(for yaml-parser, json-parser, etc.)* & get output.

2. `int swSendMsg(const int PORT, const char* SERVER_IP, char* message)` - Send message to **SecretWay**.

3. `swTest()` - Function to test work of **SecretWay API**. If it's ok this will write `hello world`.

## SecretWay (server part)

You can see **SecretWay** [here](https://github.com/shawarmateam/secretway).

