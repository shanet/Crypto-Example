#include "base64.h"

char* base64Encode(const unsigned char *message, const size_t length) {
  int encodedSize = 4 * ceil((double)length / 3);
  char *encodedMessage = (char*)malloc(encodedSize + 1);

  if(encodedMessage == NULL) {
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

  // Add a NUL terminator
  memcpy(encodedMessage, (*bufferPtr).data, (*bufferPtr).length + 1);
  encodedMessage[(*bufferPtr).length] = '\0';

  BIO_free_all(bio);
  return encodedMessage;
}

int base64Decode(const char *encodedMessage, const size_t encodedMessageLength, unsigned char **decodedMessage) {
  int decodedLength = calculateDecodedLength(encodedMessage, encodedMessageLength);
  *decodedMessage = (unsigned char*)malloc(decodedLength + 1);

  if(*decodedMessage == NULL) {
    fprintf(stderr, "Failed to allocate memory\n");
    exit(1);
  }

  BIO *bio = BIO_new_mem_buf(encodedMessage, encodedMessageLength);
  BIO *b64 = BIO_new(BIO_f_base64());
  bio = BIO_push(b64, bio);
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

  // Add a NUL terminator
  decodedLength = BIO_read(bio, *decodedMessage, encodedMessageLength);
  (*decodedMessage)[decodedLength] = '\0';

  BIO_free_all(bio);

  return decodedLength;
}

int calculateDecodedLength(const char *encodedMessage, const size_t encodedMessageLength) {
  unsigned int padding = 0;

  // Check for trailing '=''s as padding
  if(encodedMessage[encodedMessageLength - 1] == '=' && encodedMessage[encodedMessageLength - 2] == '=') {
    padding = 2;
  } else if (encodedMessage[encodedMessageLength - 1] == '=') {
    padding = 1;
  }

  return (int)encodedMessageLength * 0.75 - padding;
}
