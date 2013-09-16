#include "base64.h"

char* base64Encode(const unsigned char *message, const size_t length) {
    BIO *bio;
    BIO *b64;
    FILE* stream;

    int encodedSize = 4*ceil((double)length/3);
    char *buffer = (char*)malloc(encodedSize+1);
    if(buffer == NULL) {
        fprintf(stderr, "Failed to allocate memory\n");
        exit(1);
    }
     
    stream = fmemopen(buffer, encodedSize+1, "w");
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_fp(stream, BIO_NOCLOSE);
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, message, length);
    (void)BIO_flush(bio);
    BIO_free_all(bio);
    fclose(stream);
     
    return buffer;
}
 
int base64Decode(const char *b64message, unsigned char **buffer) {
    BIO *bio;
    BIO *b64;
    int decodeLen = calcDecodeLength(b64message);

    *buffer = (unsigned char*)malloc(decodeLen+1);
    if(*buffer == NULL) {
        fprintf(stderr, "Failed to allocate memory\n");
        exit(1);
    }
    FILE* stream = fmemopen((char*)b64message, strlen(b64message), "r");
     
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_fp(stream, BIO_NOCLOSE);
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    size_t length = BIO_read(bio, *buffer, strlen(b64message));
    (*buffer)[length] = '\0';
     
    BIO_free_all(bio);
    fclose(stream);
     
    return decodeLen;
}

int calcDecodeLength(const char *b64input) {
    int len = strlen(b64input);
    int padding = 0;
    
    // Check for trailing '=''s as padding
    if(b64input[len-1] == '=' && b64input[len-2] == '=')
        padding = 2;
    else if (b64input[len-1] == '=')
        padding = 1;
     
    return (int)len*0.75 - padding;
}
