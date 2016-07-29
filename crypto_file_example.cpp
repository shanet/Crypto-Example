#include "crypto_file_example.h"

// Note: This isn't a good way to encrypt large file (anything that can't be read into
// memory in a single buffer). A better approach for this is to read in one block at a type,
// encrypt it, write it to a file and so on.

int main(int argc, char **argv) {
  if(argc != 2) {
    fprintf(stderr, "No file argument supplied.\n");
    return 1;
  }

  Crypto crypto;

  char *encryptedFilename = encryptFile(&crypto, argv[1]);
  decryptFile(&crypto, argv[1], encryptedFilename);

  return 0;
}

char* encryptFile(Crypto *crypto, char *filename) {
  // Read the file to encrypt
  unsigned char *file;
  size_t fileLength = readFile(filename, &file);
  printf("%d bytes to be encrypted\n", (int)fileLength);

  // Encrypt the file
  unsigned char *encryptedFile;
  int encryptedFileLength = crypto->aesEncrypt((const unsigned char*)file, fileLength, &encryptedFile);

  if(encryptedFileLength == -1) {
    fprintf(stderr, "Encryption failed\n");
    exit(1);
  }
  printf("%d bytes encrypted\n", encryptedFileLength);

  // Append .enc to the filename
  char *encryptedFilename = appendToString(filename, (char*)".enc");

  #ifdef CONVERT_TO_BASE64
    // Encode the encrypted file to base64
    char *base64Buffer = base64Encode(encryptedFile, encryptedFileLength);

    // Change the encrypted file pointer to the base64 string and update the length
    free(encryptedFile);
    encryptedFile = (unsigned char*)base64Buffer;
    encryptedFileLength = strlen((char*)encryptedFile);
  #endif

  // Write the encrypted file to its own file
  writeFile(encryptedFilename, encryptedFile, encryptedFileLength);
  printf("Encrypted file written to \"%s\"\n", encryptedFilename);

  free(file);
  return encryptedFilename;
}

void decryptFile(Crypto *crypto, char *filename, char *encryptedFilename) {
  // Read the encrypted file back
  unsigned char *file;
  size_t fileLength = readFile(encryptedFilename, &file);

  #ifdef CONVERT_TO_BASE64
    // Decode the encrypted file from base64
    unsigned char *binaryBuffer;
    fileLength = base64Decode((char*)file, fileLength, &binaryBuffer);

    // Change the pointer of the string containing the file info to the decoded base64 string
    free(file);
    file = binaryBuffer;
  #endif

  // Decrypt the encrypted file
  unsigned char *decryptedFile;
  int decryptedFileLength = crypto->aesDecrypt(file, fileLength, &decryptedFile);

  if(decryptedFileLength == -1) {
    fprintf(stderr, "Decryption failed\n");
    exit(1);
  }
  printf("%d bytes decrypted\n", (int)decryptedFileLength);

  // Append .dec to the filename
  char *decryptedFilename = appendToString(filename, (char*)".dec");

  // Write the decrypted file to its own file
  writeFile(decryptedFilename, decryptedFile, decryptedFileLength);
  printf("Decrypted file written to \"%s\"\n", decryptedFilename);

  free(decryptedFile);
  free(decryptedFilename);
  free(file);
}

void writeFile(char *filename, unsigned char *file, size_t fileLength) {
  FILE *fd = fopen(filename, "wb");
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
  FILE *fd = fopen(filename, "rb");
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
