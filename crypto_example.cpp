#include "crypto_example.h"

using std::string;
using std::cin;

int main() {
  Crypto crypto;

  #ifdef PRINT_KEYS
    printKeys(&crypto);
  #endif

  while(!std::cin.eof()) {
    encryptRsa(&crypto);
    encryptAes(&crypto);
  }

  return 0;
}

void encryptRsa(Crypto *crypto) {
  // Get the message to encrypt
  string message = getMessage("Message to RSA encrypt: ");

  // Encrypt the message with RSA
  unsigned char *encryptedMessage = NULL;
  unsigned char *encryptedKey;
  unsigned char *iv;
  size_t encryptedKeyLength;
  size_t ivLength;

  // +1 on the string length argument because we want to encrypt the NUL terminator too
  int encryptedMessageLength = crypto->rsaEncrypt((const unsigned char*)message.c_str(), message.size()+1,
    &encryptedMessage, &encryptedKey, &encryptedKeyLength, &iv, &ivLength);

  if(encryptedMessageLength == -1) {
    fprintf(stderr, "Encryption failed\n");
    return;
  }

  // Print the encrypted message as a base64 string
  char* b64Message = base64Encode(encryptedMessage, encryptedMessageLength);
  printf("Encrypted message: %s\n", b64Message);

  // Decrypt the message
  char *decryptedMessage = NULL;

  int decryptedMessageLength = crypto->rsaDecrypt(encryptedMessage, (size_t)encryptedMessageLength,
    encryptedKey, encryptedKeyLength, iv, ivLength, (unsigned char**)&decryptedMessage);

  if(decryptedMessageLength == -1) {
    fprintf(stderr, "Decryption failed\n");
    return;
  }

  printf("Decrypted message: %s\n", decryptedMessage);

  // Clean up
  free(encryptedMessage);
  free(decryptedMessage);
  free(encryptedKey);
  free(iv);
  free(b64Message);
}

void encryptAes(Crypto *crypto) {
  // Get the message to encrypt
  string message = getMessage("Message to AES encrypt: ");

  // Encrypt the message with AES
  unsigned char *encryptedMessage = NULL;
  int encryptedMessageLength = crypto->aesEncrypt((const unsigned char*)message.c_str(), message.size()+1, &encryptedMessage);

  if(encryptedMessageLength == -1) {
    fprintf(stderr, "Encryption failed\n");
    return;
  }

  // Print the encrypted message as a base64 string
  char *b64Message = base64Encode(encryptedMessage, encryptedMessageLength);
  printf("Encrypted message: %s\n", b64Message);

  // Decrypt the message
  char *decryptedMessage = NULL;
  int decryptedMessageLength = crypto->aesDecrypt(encryptedMessage, (size_t)encryptedMessageLength, (unsigned char**)&decryptedMessage);

  if(decryptedMessageLength == -1) {
    fprintf(stderr, "Decryption failed\n");
    return;
  }

  printf("Decrypted message: %s\n", decryptedMessage);

  // Clean up
  free(encryptedMessage);
  free(decryptedMessage);
  free(b64Message);
}

string getMessage(const char *prompt) {
  string message;

  printf(prompt);
  fflush(stdout);

  getline(std::cin, message);
  return message;
}

void printKeys(Crypto *crypto) {
  // Write the RSA keys to stdout
  crypto->writeKeyToFile(stdout, KEY_SERVER_PRI);
  crypto->writeKeyToFile(stdout, KEY_SERVER_PUB);
  crypto->writeKeyToFile(stdout, KEY_CLIENT_PUB);

  // Write the AES key to stdout in hex
  unsigned char *aesKey;
  size_t aesKeyLength = crypto->getAesKey(&aesKey);
  printBytesAsHex(aesKey, aesKeyLength, "AES Key");

  // Write the AES IV to stdout in hex
  unsigned char *aesIv;
  size_t aesIvLength = crypto->getAesIv(&aesIv);
  printBytesAsHex(aesIv, aesIvLength, "AES IV");
}

void printBytesAsHex(unsigned char *bytes, size_t length, const char *message) {
  printf("%s: ", message);

  for(unsigned int i=0; i<length; i++) {
    printf("%02hhx", bytes[i]);
  }

  puts("");
}
