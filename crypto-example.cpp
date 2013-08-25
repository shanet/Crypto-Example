#include <stdio.h>
#include <iostream>
#include <string>

#include "base64.h"
#include "Crypto.h"

//#define PRINT_KEYS

using namespace std;

int main() {
    Crypto crypto;

    #ifdef PRINT_KEYS
        // Write the keys to stdout if compiled as such
        crypto.writeKeyToFile(stdout, KEY_SERVER_PRI);
        crypto.writeKeyToFile(stdout, KEY_SERVER_PUB);
        crypto.writeKeyToFile(stdout, KEY_CLIENT_PUB);

        unsigned char *aesKey;
        size_t aesLength = crypto.getAESKey(&aesKey);
        printf("AES key: ");
        for(int i=0; i<aesLength; i++) {
            printf("%d", aesKey[i]);
        }
        printf("\n");
    #endif

    string msg;
    unsigned char *encMsg = NULL;
    char *decMsg          = NULL;
    int encMsgLen;
    int decMsgLen;

    unsigned char *ek;
    unsigned char *iv;
    size_t ekl;
    size_t ivl;

    while(1) {
        // Get the message to encrypt
        printf("Message to RSA encrypt: ");
        fflush(stdout);
        getline(cin, msg);

        // Encrypt the message with RSA
        if((encMsgLen = crypto.rsaEncrypt((const unsigned char*)msg.c_str(), msg.size(), &encMsg, &ek, &ekl, &iv, &ivl)) == -1) {
            fprintf(stderr, "Encryption failed\n");
            return 1;
        }

        // Print the encrypted message as a base64 string
        char* b64String = base64Encode(encMsg, encMsgLen);
        printf("Encrypted message: %s\n", b64String);

        // Decrypt the message
        if((decMsgLen = crypto.rsaDecrypt(encMsg, (size_t)encMsgLen, ek, ekl, iv, ivl, (unsigned char**)&decMsg)) == -1) {
            fprintf(stderr, "Decryption failed\n");
            return 1;
        }
        printf("Decrypted message: %s\n", decMsg);

        // No one likes memory leaks
        free(encMsg);
        free(decMsg);
        free(ek);
        free(iv);
        free(b64String);
        encMsg    = NULL;
        decMsg    = NULL;
        ek        = NULL;
        iv        = NULL;
        b64String = NULL;

        // Get the message to encrypt
        printf("Message to AES encrypt: ");
        fflush(stdout);
        getline(cin, msg);

        // Encrypt the message with AES
        if((encMsgLen = crypto.aesEncrypt((const unsigned char*)msg.c_str(), msg.size(), &encMsg)) == -1) {
            fprintf(stderr, "Encryption failed\n");
            return 1;
        }

        // Print the encrypted message as a base64 string
        b64String = base64Encode(encMsg, encMsgLen);
        printf("Encrypted message: %s\n", b64String);

        // Decrypt the message
        if((decMsgLen = crypto.aesDecrypt(encMsg, (size_t)encMsgLen, (unsigned char**)&decMsg)) == -1) {
            fprintf(stderr, "Decryption failed\n");
            return 1;
        }
        printf("%d bytes decrypted\n", decMsgLen);
        printf("Decrypted message: %s\n", decMsg);

        // Memory leaks... yadda yadda yadda...
        free(encMsg);
        free(decMsg);
        free(b64String);
        encMsg    = NULL;
        decMsg    = NULL;
        b64String = NULL;
    }

    return 0;
}
