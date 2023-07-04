#ifndef CRYPTO_FILE_EXAMPLE_H
#define CRYPTO_FILE_EXAMPLE_H

#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "base64.h"
#include "Crypto.h"

void encryptFile(Crypto *crypto, char *input, char *output);
void decryptFile(Crypto *crypto, char *input, char *output);

void writeFile(char *filename, unsigned char *file, size_t fileLength);
int readFile(char *filename, unsigned char **file);

char* appendToString(char *string, char *suffix);

#endif
