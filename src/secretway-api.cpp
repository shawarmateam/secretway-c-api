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
#include <vector>
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

UserConf swParseConfig() {
    EnvParser parser;
    if (parser.load("config.env")) {
        std::string id = parser.get("USERID");
        std::string pswd = parser.get("PASSWORD");
        if (!id.empty()) {
            std::cout << "USERID: '" << id << "'" << std::endl;
            std::cout << "PASSWORD: '" << pswd << "'" << std::endl;
        } else {
            std::cout << "Incorrect config. Closing..." << std::endl;
            exit(1);
        }

        UserConf u_cfg;
        u_cfg.id = strdup((char*)id.c_str());
        u_cfg.password = strdup((char*)pswd.c_str());

        return u_cfg;
    }

    cout << "Parse failture" << endl;
    exit(1);
}

std::vector<DbIp> swParseIpList(const std::string &filename) {
    std::vector<DbIp> dbIps; // Используем вектор для динамического размера
    std::ifstream file(filename);
    std::string line;

    if (!file.is_open()) {
        std::cerr << "Не удалось открыть файл!" << std::endl;
        return dbIps; // Возвращаем пустой вектор в случае ошибки
    }

    while (std::getline(file, line)) {
        std::istringstream iss(line);
        std::string ip;
        std::string portStr;

        // Разделяем строку на IP и порт
        if (std::getline(iss, ip, ':') && std::getline(iss, portStr)) {
            DbIp dbIp;
            dbIp.ip = new char[ip.length() + 1]; // Выделяем память для IP
            std::strcpy(dbIp.ip, ip.c_str()); // Копируем IP в структуру
            dbIp.port = static_cast<short>(std::stoi(portStr)); // Преобразуем порт в short

            dbIps.push_back(dbIp); // Добавляем структуру в вектор
        }
    }

    file.close();
    return dbIps; // Возвращаем заполненный вектор
}

void freeDbIpVector(std::vector<DbIp>& db_ips) {
    for (auto& db_ip : db_ips) {
        free(db_ip.ip);
    }
}

int swSendMsg(const char* msg, const char* s_ui, UserConf *u_cfg, DbIp *db_ip) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::cerr << "Ошибка при создании сокета" << std::endl;
        return 1;
    }

    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(db_ip->port);            // Default IP is 127.0.0.1:1201 ps. 21 is max
    inet_pton(AF_INET, db_ip->ip, &serverAddress.sin_addr);

    if (connect(sock, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
        std::cerr << "Ошибка при подключении к серверу" << std::endl;
        close(sock);
        return 1;
    }
    std::cout << "Подключено к серверу!" << std::endl;

    size_t package_size = 76 + strlen(u_cfg->id) + strlen(u_cfg->password) + strlen(s_ui) + strlen(msg);
    char* package = (char*)malloc(package_size);

    memset(package, 0, package_size);

    snprintf(package, package_size,
        "{'userId': '%s', 'password': '%s', 'sendUserId': '%s', 'msg': '%s', 'client': true}",
        u_cfg->id, u_cfg->password, s_ui, msg);

    cout << "'" << package << "'" << endl;

    send(sock, package, strlen(package), 0);

    // Remove mem
    free(package);
    close(sock);

    return 0;
}

