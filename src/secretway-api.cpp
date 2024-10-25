#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <cstdio>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>
using namespace std;

struct UserConf
{
    char** db_ips;

    char* id;
    char* password;
    const char* private_key;
    const char* public_key;
    const bool client = true;
};

char* swExec(const char* cmd) {
    array<char, 128> buffer;
    string result;
    // Открываем процесс для чтения
    unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe) {
        throw runtime_error("popen() failed!");
    }
    // Читаем вывод команды
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }

    char* output = new char[result.size() + 1]; // +1 для нуль-терминатора
    strcpy(output, result.c_str());

    return output;
}

int swSendMsg(const char* msg, const char* s_ui, UserConf *u_cfg) {
    // Создаем сокет
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::cerr << "Ошибка при создании сокета" << std::endl;
        return 1;
    }

    // Указываем адрес сервера
    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(1201); // Порт сервера
    inet_pton(AF_INET, "127.0.0.1", &serverAddress.sin_addr); // IP-адрес сервера

    // Подключаемся к серверу
    if (connect(sock, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
        std::cerr << "Ошибка при подключении к серверу" << std::endl;
        close(sock);
        return 1;
    }
    std::cout << "Подключено к серверу!" << std::endl;

    char* package = swExec("./json-parser -msg \"hello from go\" -id 0 -pw hui_penis -sui 0");
    cout << "'" << package << "'" << endl;

    send(sock, package, strlen(package), 0);

    // Закрываем сокет
    close(sock);
    return 0;
}

