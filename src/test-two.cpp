#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

int main() {
    // Инициализация библиотеки OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Генерация ключей
    int keyLength = 2048; // Длина ключа
    RSA *rsa = RSA_generate_key(keyLength, RSA_F4, nullptr, nullptr);
    if (!rsa) {
        handleErrors();
    }

    // Сохранение приватного ключа в файл
    FILE *privateKeyFile = fopen("private_key.pem", "wb");
    if (!privateKeyFile) {
        handleErrors();
    }
    if (PEM_write_RSAPrivateKey(privateKeyFile, rsa, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        handleErrors();
    }
    fclose(privateKeyFile);

    // Сохранение публичного ключа в файл
    FILE *publicKeyFile = fopen("public_key.pem", "wb");
    if (!publicKeyFile) {
        handleErrors();
    }
    if (PEM_write_RSA_PUBKEY(publicKeyFile, rsa) != 1) {
        handleErrors();
    }
    fclose(publicKeyFile);

    // Освобождение ресурсов
    RSA_free(rsa);
    ERR_free_strings();
    EVP_cleanup();

    std::cout << "Ключи успешно сгенерированы и сохранены в файлы private_key.pem и public_key.pem." << std::endl;

    return 0;
}

