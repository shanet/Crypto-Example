#include "crypto_file_example.h"

// Note: This isn't a good way to encrypt large file (anything that can't be read into
// memory in a single buffer). A better approach for this is to read in one block at a type,
// encrypt it, write it to a file, and so on.

int main(int argc, char **argv) {
  if(argc != 2) {
    fprintf(stderr, "Invalid number of arguments given.\nUsage: %s [input file]\n", argv[0]);
    return 1;
  }

  Crypto crypto;

  char *encryptedOutput = appendToString(argv[1], (char*)".enc");
  char *decryptedOutput = appendToString(argv[1], (char*)".dec");

  encryptFile(&crypto, argv[1], encryptedOutput);
  decryptFile(&crypto, encryptedOutput, decryptedOutput);

  free(encryptedOutput);
  free(decryptedOutput);

  return 0;
}

void encryptFile(Crypto *crypto, char *input, char *output) {
  // Read the file to encrypt
  unsigned char *plaintext;
  size_t plainTextLength = readFile(input, &plaintext);
  printf("%d bytes to be encrypted\n", (int)plainTextLength);

  // Encrypt the file
  unsigned char *ciphertext;
  int ciphertextLength = crypto->aesEncrypt((const unsigned char*)plaintext, plainTextLength, &ciphertext);

  if(ciphertextLength == -1) {
    fprintf(stderr, "Encryption failed\n");
    exit(1);
  }
  printf("%d bytes encrypted\n", ciphertextLength);

  // Encode the encrypted file to base64
  char *base64Ciphertext = base64Encode(ciphertext, ciphertextLength);

  // Write the encrypted file to its own file
  writeFile(output, (unsigned char*)base64Ciphertext, strlen((char*)base64Ciphertext));
  printf("Encrypted file written to \"%s\"\n", output);

  free(plaintext);
  free(ciphertext);
  free(base64Ciphertext);
}

void decryptFile(Crypto *crypto, char *input, char *output) {
  // Read the encrypted file back
  unsigned char *base64Ciphertext;
  size_t base64CiphertextLength = readFile(input, &base64Ciphertext);

  // Decode the encrypted file from base64
  unsigned char *ciphertext;
  size_t ciphertextLength = base64Decode((char*)base64Ciphertext, base64CiphertextLength, &ciphertext);

  // Decrypt the encrypted file
  unsigned char *plaintext;
  int plaintextLength = crypto->aesDecrypt(ciphertext, ciphertextLength, &plaintext);

  if(plaintextLength == -1) {
    fprintf(stderr, "Decryption failed\n");
    exit(1);
  }
  printf("%d bytes decrypted\n", (int)plaintextLength);

  // Write the decrypted file to its own file
  writeFile(output, plaintext, plaintextLength);
  printf("Decrypted file written to \"%s\"\n", output);

  free(base64Ciphertext);
  free(ciphertext);
  free(plaintext);
}

void writeFile(char *filename, unsigned char *file, size_t fileLength) {
  FILE *fd = fopen(filename, "w");
  if(fd == NULL) {
    fprintf(stderr, "Failed to open file: %s\n", strerror(errno));
    exit(1);
  }

  size_t bytesWritten = fwrite(file, 1, fileLength, fd);

  if(bytesWritten != fileLength) {
    fprintf(stderr, "Failed to write file\n");
    exit(1);
  }

  fclose(fd);
}

int readFile(char *filename, unsigned char **file) {
  FILE *fd = fopen(filename, "r");
  if(fd == NULL) {
    fprintf(stderr, "Failed to open file: %s\n", strerror(errno));
    exit(1);
  }

  // Determine size of the file
  fseek(fd, 0, SEEK_END);
  size_t fileLength = ftell(fd);
  fseek(fd, 0, SEEK_SET);

  // Allocate space for the file
  *file = (unsigned char*)malloc(fileLength);
  if(*file == NULL) {
    fprintf(stderr, "Failed to allocate memory\n");
    exit(1);
  }

  // Read the file into the buffer
  size_t bytesRead = fread(*file, 1, fileLength, fd);

  if(bytesRead != fileLength) {
    fprintf(stderr, "Error reading file\n");
    exit(1);
  }

  fclose(fd);

  return fileLength;
}

char* appendToString(char *string, char *suffix) {
  char *appenedString = (char*)malloc(strlen(string) + strlen(suffix) + 1);

  if(appenedString == NULL) {
    fprintf(stderr, "Failed to allocate memory\n");
    exit(1);
  }

  sprintf(appenedString, "%s%s", string, suffix);
  return appenedString;
}
