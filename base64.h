#ifndef BASE64_H
#define BASE64_H

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>

#include <math.h>
#include <stdio.h>
#include <string.h>

char* base64Encode(const unsigned char *buffer, const size_t length);
int base64Decode(const char *b64message, const size_t length, unsigned char **buffer);
int calcDecodeLength(const char *b64input, const size_t length);

#endif
