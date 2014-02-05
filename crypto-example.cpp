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
        // Write the RSA keys to stdout
        crypto.writeKeyToFile(stdout, KEY_SERVER_PRI);
        crypto.writeKeyToFile(stdout, KEY_SERVER_PUB);
        crypto.writeKeyToFile(stdout, KEY_CLIENT_PUB);

        // Write the AES key to stdout in hex
        unsigned char *aesKey;
        size_t aesLength = crypto.getAESKey(&aesKey);
        printf("AES key: ");
        for(unsigned int i=0; i<aesLength; i++) {
            printf("%x", aesKey[i]);
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

    while(!cin.eof()) {
        // Get the message to encrypt
        printf("Message to RSA encrypt: ");
        fflush(stdout);
        getline(cin, msg);

        // Encrypt the message with RSA
        // Note the +1 tacked on to the string length argument. We want to encrypt the NUL terminator too. If we don't,
        // we would have to put it back after decryption, but it's easier to keep it with the string.
        if((encMsgLen = crypto.rsaEncrypt((const unsigned char*)msg.c_str(), msg.size()+1, &encMsg, &ek, &ekl, &iv, &ivl)) == -1) {
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
        if((encMsgLen = crypto.aesEncrypt((const unsigned char*)msg.c_str(), msg.size()+1, &encMsg)) == -1) {
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
