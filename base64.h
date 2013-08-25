#ifndef BASE64_H

#include <openssl/bio.h>
#include <openssl/evp.h>

#include <math.h>
#include <stdio.h>
#include <string.h>

char* base64Encode(const unsigned char *buffer, const size_t length);
int base64Decode(const char *b64message, unsigned char **buffer);
int calcDecodeLength(const char *b64input);

#endif
