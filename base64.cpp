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
 
int base64Decode(const char *b64message, const size_t length, unsigned char **buffer) {
    BIO *bio;
    BIO *b64;
    int decodedLength = calcDecodeLength(b64message, length);

    *buffer = (unsigned char*)malloc(decodedLength+1);
    if(*buffer == NULL) {
        fprintf(stderr, "Failed to allocate memory\n");
        exit(1);
    }
    FILE* stream = fmemopen((char*)b64message, length, "r");
     
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_fp(stream, BIO_NOCLOSE);
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    decodedLength = BIO_read(bio, *buffer, length);
    (*buffer)[decodedLength] = '\0';
     
    BIO_free_all(bio);
    fclose(stream);
     
    return decodedLength;
}

int calcDecodeLength(const char *b64input, const size_t length) {
    int padding = 0;
    
    // Check for trailing '=''s as padding
    if(b64input[length-1] == '=' && b64input[length-2] == '=')
        padding = 2;
    else if (b64input[length-1] == '=')
        padding = 1;
     
    return (int)length*0.75 - padding;
}
