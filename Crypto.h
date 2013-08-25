#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <stdio.h>
#include <string>
#include <string.h>

#ifndef CRYPTO_H
#define CRYPTO_H

#define RSA_KEYLEN 2048
#define AES_KEYLEN 256
#define AES_ROUNDS 6

#define PSUEDO_CLIENT

//#define USE_PBKDF

#define SUCCESS 0
#define FAILURE -1

#define KEY_SERVER_PRI 0
#define KEY_SERVER_PUB 1
#define KEY_CLIENT_PUB 2
#define KEY_AES        3
#define KEY_AES_IV     4

class Crypto {

public:
    Crypto();

    Crypto(unsigned char *remotePubKey, size_t remotePubKeyLen);

    ~Crypto();

    int rsaEncrypt(const unsigned char *msg, size_t msgLen, unsigned char **encMsg, unsigned char **ek, size_t *ekl, unsigned char **iv, size_t *ivl);

    int aesEncrypt(const unsigned char *msg, size_t msgLen, unsigned char **encMsg);

    int rsaDecrypt(unsigned char *encMsg, size_t encMsgLen, unsigned char *ek, size_t ekl, unsigned char *iv, size_t ivl, unsigned char **decMsg);

    int aesDecrypt(unsigned char *encMsg, size_t encMsgLen, unsigned char **decMsg);

    int writeKeyToFile(FILE *fd, int key);

    int getRemotePubKey(unsigned char **pubKey);

    int setRemotePubKey(unsigned char *pubKey, size_t pubKeyLen);

    int getLocalPubKey(unsigned char **pubKey);

    int getLocalPriKey(unsigned char **priKey);

    int getAESKey(unsigned char **aesKey);

    int setAESKey(unsigned char *aesKey, size_t aesKeyLen);

    int getAESIv(unsigned char **aesIv);

    int setAESIv(unsigned char *aesIv, size_t aesIvLen);

private:
    static EVP_PKEY *localKeypair;
    EVP_PKEY *remotePubKey;

    EVP_CIPHER_CTX *rsaEncryptCtx;
    EVP_CIPHER_CTX *aesEncryptCtx;

    EVP_CIPHER_CTX *rsaDecryptCtx;
    EVP_CIPHER_CTX *aesDecryptCtx;

    unsigned char *aesKey;
    unsigned char *aesIV;

    int init();
    int genTestClientKey();
};

#endif
