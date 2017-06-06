#include "base64.h"

char* base64Encode(const unsigned char *message, const size_t length) {
  int encodedSize = 4 * ceil((double)length / 3);
  char *b64text = (char*)malloc(encodedSize + 1);

  if(b64text == NULL) {
    fprintf(stderr, "Failed to allocate memory\n");
    exit(1);
  }

  BIO *b64 = BIO_new(BIO_f_base64());
  BIO *bio = BIO_new(BIO_s_mem());
  bio = BIO_push(b64, bio);
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

  BIO_write(bio, message, length);
  BIO_flush(bio);

  BUF_MEM *bufferPtr;
  BIO_get_mem_ptr(bio, &bufferPtr);
  BIO_set_close(bio, BIO_CLOSE);

  memcpy(b64text, (*bufferPtr).data, (*bufferPtr).length + 1);
  
  BIO_free_all(bio);
  return b64text;
}

int base64Decode(const char *b64message, const size_t length, unsigned char **buffer) {
  int decodedLength = calcDecodeLength(b64message, length);
  *buffer = (unsigned char*)malloc(decodedLength + 1);

  if(*buffer == NULL) {
    fprintf(stderr, "Failed to allocate memory\n");
    exit(1);
  }

  BIO *bio = BIO_new_mem_buf(b64message, -1);
  BIO *b64 = BIO_new(BIO_f_base64());
  bio = BIO_push(b64, bio);
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

  decodedLength = BIO_read(bio, *buffer, strlen(b64message));
  (*buffer)[decodedLength] = '\0';

  BIO_free_all(bio);

  return decodedLength;
}

int calcDecodeLength(const char *b64input, const size_t length) {
  unsigned int padding = 0;

  // Check for trailing '=''s as padding
  if(b64input[length - 1] == '=' && b64input[length - 2] == '=') {
    padding = 2;
  } else if (b64input[length - 1] == '=') {
    padding = 1;
  }

  return (int)length * 0.75 - padding;
}
