#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <string.h>
#include <cstdlib>
#include <ctime>

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
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

std::string swGenSalt(int length) {
    const std::string characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                    "abcdefghijklmnopqrstuvwxyz"
                                    "0123456789"
                                    "!@$%^*_+.";
    std::string salt;
    srand(static_cast<unsigned int>(time(0))); // init

    for (int i = 0; i < length; ++i) {
        salt += characters[rand() % characters.size()];
    }

    return salt;
}

std::string swCypherMsg(std::string package, RSA* pub_key, std::string salt) {
    std::string cypheredMsg = "SW"+rsaEncrypt(pub_key, package)+":"+salt;
    return cypheredMsg;
}

int main() {
    // Загрузка ключей
    RSA* publicKey = createRSAWithFilename("public_key.pem", 1);
    RSA* privateKey = createRSAWithFilename("private_key.pem", 0);

    std::string message = "Hello, World!";
    //std::cout << "Original Message: " << message << std::endl;

    // Шифрование
    //std::string encryptedMessage = rsaEncrypt(publicKey, message);
    std::string encryptedMessage = swCypherMsg(message, publicKey, swGenSalt(120));
    std::cout << encryptedMessage << std::endl;

    // Расшифрование
    //std::string decryptedMessage = rsaDecrypt(privateKey, encryptedMessage);
    //std::cout << "Decrypted Message: " << decryptedMessage << std::endl;

    // Освобождение ресурсов
    RSA_free(publicKey);
    RSA_free(privateKey);

    return 0;
}

