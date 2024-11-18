// main libs
#include <iostream>
#include <cstring>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

// important libs
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

// For RSA
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <ctime>

// mongo CXX driver
#include <mongocxx/client.hpp>
#include <mongocxx/instance.hpp>
#include <mongocxx/uri.hpp>
#include <mongocxx/stdx.hpp>

// bson CXX driver
#include <bsoncxx/json.hpp>
#include <bsoncxx/builder/stream/document.hpp>

// other
#include <utility>

using namespace std;

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

class EnvParser {
public:
    bool load(const string& filename) {
        ifstream file(filename);
        if (!file.is_open()) {
            cerr << "[FATAL] Could not open the file: " << filename << endl;
            return false;
        }

        string line;
        while (getline(file, line)) {
            trim(line);
            // ignore empty str & comments
            if (line.empty() || line[0] == '#')
                continue;

            // divide str on key & val
            size_t pos = line.find('=');
            if (pos == string::npos) {
                cerr << "[ERROR] Invalid line: " << line << endl;  continue;
            }

            string key = trim(line.substr(0, pos));
            string value = trim(line.substr(pos+1));

            envMap[key] = value;
        }

        file.close();
        return true;
    }

    string get(const string& key) const {
        auto it = envMap.find(key);
        if (it != envMap.end())
            return it->second;
        return "";
    }

private:
    map<string, string> envMap;

    string trim(const string& str) { // rm space
        size_t first = str.find_first_not_of(' ');
        if (first == string::npos) return "";
        size_t last = str.find_last_not_of(' ');

        return str.substr(first, (last - first + 1));
    }
};

UserConf swParseConfig() {
    EnvParser parser;
    if (parser.load("config.env")) {
        string id = parser.get("USERID");
        string pswd = parser.get("PASSWORD");
        if (id.empty()) {
            cout << "[FATAL] Incorrect config." << endl;
            exit(1);
        }

        UserConf u_cfg;
        u_cfg.id = strdup((char*)id.c_str());
        u_cfg.password = strdup((char*)pswd.c_str());

        return u_cfg;
    }
    // by default
    cout << "[FATAL] Parse failture." << endl;
    exit(1);
}

RSA* loadServerKey(const string& publicKeyStr) {
    BIO* bio = BIO_new_mem_buf(publicKeyStr.c_str(), -1);
    if (!bio) {
        cerr << "[FATAL] Failed to create BIO." << endl;
        exit(1);
    }

    RSA* rsa = PEM_read_bio_RSA_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!rsa) {
        cerr << "[FATAL] Failed to read public key." << endl;
        exit(1);
    }

    return rsa;
}

std::string getServerKey(const char *ip) {
    cout << "IP: '" << ip << "'\n";
    // Инициализация экземпляра MongoDB
    mongocxx::instance instance{};
    mongocxx::client client{mongocxx::uri{}};

    // Подключение к базе данных и коллекции
    auto db = client["servers_bd"];
    auto collection = db["offacc_servers"];

    // Создание фильтра для поиска по server_ip
    bsoncxx::builder::stream::document filter_builder;
    string ip_str(ip);
    filter_builder << "server_ip" << ip_str;

    // Выполнение запроса
    auto cursor = collection.find(filter_builder.view());

    // Обработка результатов
    for (auto&& doc : cursor) {
        // Извлечение public_key из документа
        auto public_key = std::string{doc["public_key"].get_utf8().value}; // Преобразование в std::string
        return public_key; // Возвращаем найденный public_key
    }

    cout << "[FATAL] no public_key" << endl;
    exit(3);
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

vector<DbIp> swParseIpList(const string &filename) {
    vector<DbIp> dbIps;
    ifstream file(filename);
    string line;

    if (!file.is_open()) {
        cerr << "[FATAL] Couldn't open file." << endl;
        exit(1);
    }

    while (getline(file, line)) {
        istringstream iss(line);
        string ip;
        string portStr;

        // Divide str by port & ip
        if (getline(iss, ip, ':') && getline(iss, portStr)) {
            DbIp dbIp;
            dbIp.ip = new char[ip.length() + 1]; // allocate mem for IP
            strcpy(dbIp.ip, ip.c_str());
            dbIp.port = static_cast<short>(stoi(portStr)); // Parse port into short

            dbIps.push_back(dbIp); // adding struct to vector
        }
    }

    file.close();
    return dbIps;
}

void freeDbIpVector(vector<DbIp>& db_ips) {
    for (auto& db_ip : db_ips) free(db_ip.ip);
}

RSA* createRSAWithFilename(const char* filename, int public_key) {
    FILE* fp = fopen(filename, "rb");
    if (fp == nullptr) {
        cerr << "Unable to open file " << filename << endl;
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

string rsaEncrypt(RSA *rsa, const string& message) {
    int rsa_len = RSA_size(rsa);
    unsigned char* encrypted = new unsigned char[rsa_len];

    int result = RSA_public_encrypt(message.length(), (unsigned char*)message.c_str(), encrypted, rsa, RSA_PKCS1_OAEP_PADDING);
    if (result == -1) {
        handleErrors();
    }

    string encryptedMessage(reinterpret_cast<char*>(encrypted), result);
    delete[] encrypted;
    return encryptedMessage;
}

string rsaDecrypt(RSA* rsa, const string& encryptedMessage) {
    int rsa_len = RSA_size(rsa);
    unsigned char *decrypted = new unsigned char[rsa_len];

    int result = RSA_private_decrypt(encryptedMessage.length(), (unsigned char*)encryptedMessage.c_str(), decrypted, rsa, RSA_PKCS1_OAEP_PADDING);
    if (result == -1) {
        handleErrors();
    }

    string decryptedMessage(reinterpret_cast<char*>(decrypted), result);
    delete[] decrypted;
    return decryptedMessage;
}

string swGenSalt() {
    const string characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                    "abcdefghijklmnopqrstuvwxyz"
                                    "0123456789"
                                    "!@$%^*_+.";
    string salt;
    srand(static_cast<unsigned int>(time(0))); // init ranrom

    for (int i = 0; i < 120; ++i) {
        salt += characters[rand() % characters.size()];
    }

    char *res = new char[salt.size() + 1];
    strcpy(res, salt.c_str());
    return res;
}

string swDecryptMsg(void *pri_key, string e_msg) {
    if (e_msg[0] != 'S' || e_msg[1] != 'W') {
        cout << "[ERROR] Invalid message (swDecryptMsg)" << endl;
        exit(1);
    } // check SW mark

    e_msg.erase(0, 2); // Remove SW mark
    MsgCyph msg_struct;
    msg_struct.cyph_msg = e_msg.substr(0, 2049); // index of RSA msg end
    msg_struct.salt = e_msg.substr(2050);        // to skip ":"
    string msg = rsaDecrypt((RSA*)pri_key, msg_struct.cyph_msg);

    return msg;
}

string swCypherMsg(string package, void* pub_key, string salt) {
    cout << "In SW cypher msg" << endl;
    return "SW"+rsaEncrypt((RSA*)pub_key, package)+":"+salt;
}

const char* parseIp(DbIp *db_ip) {
    string ip(db_ip->ip);
    if (0 != std::string::npos) ip.replace(0, 9, "localhost");

    return (ip+":"+to_string(db_ip->port)).c_str();
}

int swSendMsg(string msg, const char* s_ui, UserConf *u_cfg, DbIp *db_ip) {
    if (u_cfg->public_key == NULL || u_cfg->private_key == NULL) { // Check on public & private keys
        cerr << "No swLoadKeys()" << endl;
        return 1;
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        cerr << "[FATAL] Error during creating socket" << endl;
        return 1;
    }

    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(db_ip->port);            // Default IP is 127.0.0.1:1201 ps. 21 is max
    inet_pton(AF_INET, db_ip->ip, &serverAddress.sin_addr);

    if (connect(sock, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
        cerr << "[FATAL] Error during connect to server" << endl;
        close(sock);
        return 1;
    }
    //                     TODO: change to data from DbIp  --\|
   
    //const string server_key_str = getServerKey(parseIp(db_ip));
    const string server_key_str = getServerKey("localhost:1201");
    cout << server_key_str << endl;

    RSA *server_key = loadServerKey(server_key_str);   // get server key
    //string msg_salt = swGenSalt();                     // gen salt
    //char *msg_salt_c = new char[msg_salt.size()+1];    // alloc char *
    //strcpy(msg_salt_c, msg_salt.c_str());              // get salt as char *

    cout << "Next is cyphered_msg" << endl;
    string cyphered_msg = swCypherMsg("SECRETWAYSALTMARK"+msg, (void *)server_key, "SECRETWAYSALTMARK"); // encrypt msg
    cout << "End of cyphered_msg" << endl;

    size_t package_size = 89+17 // strlen("SECRETWAYSALTMARK") == 17
        + strlen(u_cfg->id)
        + strlen(u_cfg->password)
        + strlen(s_ui)
        + cyphered_msg.size();
    cout << "\n\n\nSIZE OF MSG: " << package_size << endl;

    char* package = (char*)malloc(package_size);
    memset(package, 0, package_size);

    snprintf(package, package_size,
        "{'userId': '%s', 'password': '%s', 'sendUserId': '%s', 'msg': '%s', 'client': true, 'salt': 'SECRETWAYSALTMARK'}",
        u_cfg->id, u_cfg->password, s_ui, cyphered_msg);

    cout << "'" << package << "'" << endl;
    //                                              TEST (TO SEND 4 URSELF)
    string package_cyph = swCypherMsg(package, u_cfg->public_key, swGenSalt());
    const char *package_char = package_cyph.c_str();

    cout << package_cyph.length() << endl;
    send(sock, package_char, strlen(package_char), 0);

    // Remove mem
    free(package);
    close(sock);

    return 0;
}

void swLoadKeys(UserConf *u_cfg, string pu_key, string pr_key) {
    u_cfg->public_key = createRSAWithFilename(pu_key.c_str(), 1);
    u_cfg->private_key = createRSAWithFilename(pr_key.c_str(), 0);
}

void swLoadServerKey(DbIp *db_ip, string pr_key) {
    db_ip->private_key = createRSAWithFilename(pr_key.c_str(), 1);
}
