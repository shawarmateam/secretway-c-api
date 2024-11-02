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
#include "secretway-api.h"

#include <fstream>
#include <sstream>
#include <map>

using namespace std;

class EnvParser {
public:
    bool load(const std::string& filename) {
        std::ifstream file(filename);
        if (!file.is_open()) {
            std::cerr << "Could not open the file: " << filename << std::endl;
            return false;
        }

        std::string line;
        while (std::getline(file, line)) {
            trim(line);
            // ignore empty str & comments
            if (line.empty() || line[0] == '#') {
                continue;
            }

            // divide str on key & val
            size_t pos = line.find('=');
            if (pos == std::string::npos) {
                std::cerr << "Invalid line: " << line << std::endl;
                continue;
            }

            std::string key = trim(line.substr(0, pos));
            std::string value = trim(line.substr(pos + 1));

            envMap[key] = value;
        }

        file.close();
        return true;
    }

    std::string get(const std::string& key) const {
        auto it = envMap.find(key);
        if (it != envMap.end()) {
            return it->second;
        }
        return "";
    }

private:
    std::map<std::string, std::string> envMap;

    std::string trim(const std::string& str) { // rm space
        size_t first = str.find_first_not_of(' ');
        if (first == std::string::npos) return "";
        size_t last = str.find_last_not_of(' ');
        return str.substr(first, (last - first + 1));
    }
};

UserConf* swParseConfig() {
    EnvParser parser;
    if (parser.load("config.env")) {
        std::string id = parser.get("USERID");
        std::string pswd = parser.get("PASSWORD");
        if (!id.empty()) {
            std::cout << "USERID: '" << id << "'" << std::endl;
            std::cout << "PASSWORD: '" << pswd << "'" << std::endl;
        } else {
            std::cout << "USERID not found. Closing..." << std::endl;
        }

        UserConf* u_cfg;
        u_cfg->id = (char*)id.c_str();
        u_cfg->password = (char*)pswd.c_str();

        return u_cfg;
    }

    return NULL;
}

char* swExec(const char* cmd) {
    array<char, 128> buffer;
    string result;
    unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe) {
        throw runtime_error("popen() failed!");
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }

    char* output = new char[result.size() + 1]; // +1 для нуль-терминатора
    strcpy(output, result.c_str());

    return output;
}

int swSendMsg(const char* msg, const char* s_ui, UserConf *u_cfg) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::cerr << "Ошибка при создании сокета" << std::endl;
        return 1;
    }

    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(1201); // Порт сервера
    inet_pton(AF_INET, "127.0.0.1", &serverAddress.sin_addr); // IP-адрес сервера

    if (connect(sock, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
        std::cerr << "Ошибка при подключении к серверу" << std::endl;
        close(sock);
        return 1;
    }
    std::cout << "Подключено к серверу!" << std::endl;

//    sprintf(package,
//"{'userId': '%s', 'password': '%s', 'sendUserId': '%s', 'msg': '%s', 'client': true}", u_cfg->id, u_cfg->password, s_ui, msg);
    size_t package_size = 76 + strlen(u_cfg->id) + strlen(u_cfg->password) + strlen(s_ui) + strlen(msg);
    char* package = (char*)malloc(package_size);

    memset(package, 0, package_size);

    snprintf(package, package_size,
        "{'userId': '%s', 'password': '%s', 'sendUserId': '%s', 'msg': '%s', 'client': true}",
        u_cfg->id, u_cfg->password, s_ui, msg);

    cout << "'" << package << "'" << endl;

    send(sock, package, strlen(package), 0);

    close(sock);
    return 0;
}

