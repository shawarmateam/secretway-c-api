#include <iostream>
#include <cstring>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>
#include "secretway-api.h"
#include <vector>
#include <fstream>
#include <sstream>
#include <map>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <ctime>

#include <mongocxx/client.hpp>
#include <mongocxx/instance.hpp>
#include <mongocxx/uri.hpp>

#include <mongocxx/stdx.hpp>
#include <bsoncxx/json.hpp>
#include <bsoncxx/builder/stream/document.hpp>
#include <iostream>

using namespace std;

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

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



RSA* loadServerKey(const std::string& publicKeyStr) {
    cout << "start of loadServerKey" << endl;
    BIO* bio = BIO_new_mem_buf(publicKeyStr.c_str(), -1);
    cout << "BIO cteated!" << endl;
    if (!bio) {
        std::cerr << "Failed to create BIO" << std::endl;
        return nullptr;
    }

    RSA* rsa = PEM_read_bio_RSA_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!rsa) {
        std::cerr << "Failed to read public key" << std::endl;
        return nullptr;
    }

    return rsa;
}

std::string getServerKey(char *ip) {
    mongocxx::instance instance{};
    mongocxx::client client{mongocxx::uri{"mongodb://localhost:27017"}};

    auto db = client["servers_bd"];
    auto collection = db["offacc_servers"];

    bsoncxx::builder::stream::document filter_builder;
    filter_builder << "server_ip" << ip;

    auto cursor = collection.find(filter_builder.view());

    for (auto&& doc : cursor) {
        auto public_key = doc["public_key"].get_utf8().value;
        std::string str(public_key);
        return str;
    }
    cout << "[FATAL] no public_key found" << endl;
    exit(1);
}

int swGenKeys(char *pu_key, char *pr_key) {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    int keyLength = 2048;
    RSA *rsa = RSA_generate_key(keyLength, RSA_F4, nullptr, nullptr);
    if (!rsa) handleErrors();

    FILE *privateKeyFile = fopen(pr_key, "wb");

    if (!privateKeyFile) handleErrors();
    if (PEM_write_RSAPrivateKey(privateKeyFile, rsa, nullptr, nullptr, 0, nullptr, nullptr) != 1) handleErrors();
    fclose(privateKeyFile);

    FILE *publicKeyFile = fopen(pu_key, "wb");

    if (!publicKeyFile) handleErrors();
    if (PEM_write_RSA_PUBKEY(publicKeyFile, rsa) != 1) handleErrors();

    fclose(publicKeyFile);

    RSA_free(rsa);
    ERR_free_strings();
    EVP_cleanup();
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

RSA* createRSAWithFilename(const char* filename, int public_key) {
    FILE* fp = fopen(filename, "rb");
    if (fp == nullptr) {
        std::cerr << "Unable to open file " << filename << std::endl;
        return nullptr;
    }

    RSA* rsa = nullptr;
    if (public_key) {
        rsa = PEM_read_RSA_PUBKEY(fp, &rsa, nullptr, nullptr);
    } else {
        rsa = PEM_read_RSAPrivateKey(fp, &rsa, nullptr, nullptr);
    }

    fclose(fp);
    return rsa;
}

std::string rsaEncrypt(RSA* rsa, const std::string& message) {
    int rsa_len = RSA_size(rsa);
    unsigned char* encrypted = new unsigned char[rsa_len];

    int result = RSA_public_encrypt(message.length(), (unsigned char*)message.c_str(), encrypted, rsa, RSA_PKCS1_OAEP_PADDING);
    if (result == -1) {
        handleErrors();
    }

    std::string encryptedMessage(reinterpret_cast<char*>(encrypted), result);
    delete[] encrypted;
    return encryptedMessage;
}

std::string rsaDecrypt(RSA* rsa, const std::string& encryptedMessage) {
    int rsa_len = RSA_size(rsa);
    unsigned char* decrypted = new unsigned char[rsa_len];

    int result = RSA_private_decrypt(encryptedMessage.length(), (unsigned char*)encryptedMessage.c_str(), decrypted, rsa, RSA_PKCS1_OAEP_PADDING);
    if (result == -1) {
        handleErrors();
    }

    std::string decryptedMessage(reinterpret_cast<char*>(decrypted), result);
    delete[] decrypted;
    return decryptedMessage;
}

std::string swGenSalt() {
    const std::string characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                    "abcdefghijklmnopqrstuvwxyz"
                                    "0123456789"
                                    "!@$%^*_+.";
    std::string salt;
    srand(static_cast<unsigned int>(time(0))); // init

    for (int i = 0; i < 120; ++i) {
        salt += characters[rand() % characters.size()];
    }

    char *res = new char[salt.size() + 1];
    std::strcpy(res, salt.c_str());
    return res;
}

std::string swDecryptMsg(void *pri_key, std::string e_msg) {
    if (e_msg[0] != 'S' || e_msg[1] != 'W') {
        cout << "[ERROR] Invalid message (swDecryptMsg)" << endl;
        exit(1);
    }

    e_msg.erase(0, 2); // Remove SW mark
    MsgCyph msg_struct;
    msg_struct.cyph_msg = e_msg.substr(0, 2049); // index of RSA msg end
    msg_struct.salt = e_msg.substr(2050);        // to skip ":"
    std::string msg = rsaDecrypt((RSA*)pri_key, msg_struct.cyph_msg);
    cout << "MSG: " << msg << endl;
    return msg;
}

std::string swCypherMsg(std::string package, void* pub_key, std::string salt) {

    std::string cypheredMsg = "SW"+rsaEncrypt((RSA*)pub_key, package)+":"+salt;
    return cypheredMsg;
}

int swSendMsg(const char* msg, const char* s_ui, UserConf *u_cfg, DbIp *db_ip) {
    if (u_cfg->public_key == NULL || u_cfg->private_key == NULL) { // Check on public & private keys
        std::cerr << "No swLoadKeys()" << std::endl;
        return 1;
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::cerr << "[FATAL] Error during creating socket" << std::endl;
        exit(1);
    }

    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(db_ip->port);            // Default IP is 127.0.0.1:1201 ps. 21 is max
    inet_pton(AF_INET, db_ip->ip, &serverAddress.sin_addr);

    if (connect(sock, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
        std::cerr << "[FATAL] Error during connect to server" << std::endl;
        close(sock);
        exit(1);
    }
    std::cout << "Connected to server!" << std::endl;

    //                     TODO: change to data from DbIp  --\|
    const std::string server_key_str = getServerKey("localhost:1201");

    cout << "Server key getted!" << endl;
    RSA *server_key = loadServerKey(server_key_str);                    // get server key
    cout << "server key loaded" << endl;
    std::string msg_salt = swGenSalt();                                                          // gen salt
    char *msg_salt_c = new char[msg_salt.size()+1];
    std::strcpy(msg_salt_c, msg_salt.c_str());                                                   // get salt as char *

    std::string cyphered_msg = swCypherMsg(strcat(msg_salt_c, msg), server_key, msg_salt); // encrypt msg
    cout << "Msg cyphered!" << endl;
    cout << cyphered_msg << endl;

    size_t package_size = 76 + strlen(u_cfg->id) + strlen(u_cfg->password) + strlen(s_ui) + cyphered_msg.size();
    char* package = (char*)malloc(package_size);
    memset(package, 0, package_size);

    snprintf(package, package_size,
        "{'userId': '%s', 'password': '%s', 'sendUserId': '%s', 'msg': '%s', 'client': true}", // TODO: добавить 'salt': "<соль>"
        u_cfg->id, u_cfg->password, s_ui, msg);

    cout << "'" << package << "'" << endl;
    //                                              TEST (TO SEND 4 URSELF)
    std::string package_cyph = swCypherMsg(package, u_cfg->public_key, swGenSalt());
    const char *package_char = package_cyph.c_str();

    std::cout << package_cyph.length() << std::endl;
    std::cout << strlen(package_char) << std::endl;
    send(sock, package_char, strlen(package_char), 0);

    // Remove mem
    free(package);
    close(sock);

    return 0;
}

void swLoadKeys(UserConf *u_cfg, std::string pu_key, std::string pr_key) {
    u_cfg->public_key = createRSAWithFilename(pu_key.c_str(), 1);
    u_cfg->private_key = createRSAWithFilename(pr_key.c_str(), 0);
}
