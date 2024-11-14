#include <jni.h>
#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

using namespace std;

extern "C" {

    struct MsgCyph
    {
        string cyph_msg;
        string salt;
    };

    std::string base64_decode(const std::string &in) {
        BIO *bio, *b64;
        BUF_MEM *bufferPtr;
        int decodeLen = (in.length() * 3) / 4;
        std::string out(decodeLen, '\0');

        b64 = BIO_new(BIO_f_base64());
        bio = BIO_new_mem_buf(in.data(), in.length());
        bio = BIO_push(b64, bio);
        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // Ignore newlines

        int actualLen = BIO_read(bio, &out[0], in.length());
        out.resize(actualLen);
        BIO_free_all(bio);

        return out;
    }

    RSA* base64toRsa(const std::string &base64Key) {
        std::string decodedKey = base64_decode(base64Key);
        BIO *bio = BIO_new_mem_buf(decodedKey.data(), decodedKey.size());
        RSA *rsa = PEM_read_bio_RSA_PUBKEY(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        return rsa;
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


    JNIEXPORT void JNICALL Java_MyJavaClass_swDecryptMsg(JNIEnv *env, jobject obj, jstring msg, jstring pr_key) {
        const char *pr_key_c = env->GetStringUTFChars(jStr, nullptr);
        std::string pr_key_str(pr_key_c);
        env->ReleaseStringUTFChars(pr_key, pr_key_c);

        RSA *private_key = base64toRsa(pr_key_str);
        return swDecryptMsg((void *)private_key, msg);
    }
}

