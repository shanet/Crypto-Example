#include "Crypto.h"

using namespace std;

EVP_PKEY* Crypto::localKeypair;

Crypto::Crypto() {
  localKeypair = NULL;
  remotePublicKey = NULL;

  #ifdef PSEUDO_CLIENT
    generateRsaKeypair(&remotePublicKey);
  #endif

  init();
}

Crypto::Crypto(unsigned char *remotePublicKey, size_t remotePublicKeyLength) {
  localKeypair = NULL;
  this->remotePublicKey = NULL;

  setRemotePublicKey(remotePublicKey, remotePublicKeyLength);
  init();
}

Crypto::~Crypto() {
  EVP_PKEY_free(remotePublicKey);

  EVP_CIPHER_CTX_free(rsaEncryptContext);
  EVP_CIPHER_CTX_free(aesEncryptContext);

  EVP_CIPHER_CTX_free(rsaDecryptContext);
  EVP_CIPHER_CTX_free(aesDecryptContext);

  free(aesKey);
  free(aesIv);
}

int Crypto::init() {
  // Initalize contexts
  rsaEncryptContext = EVP_CIPHER_CTX_new();
  aesEncryptContext = EVP_CIPHER_CTX_new();

  rsaDecryptContext = EVP_CIPHER_CTX_new();
  aesDecryptContext = EVP_CIPHER_CTX_new();

  // Check if any of the contexts initializations failed
  if(rsaEncryptContext == NULL || aesEncryptContext == NULL || rsaDecryptContext == NULL || aesDecryptContext == NULL) {
    return FAILURE;
  }

  // Generate RSA and AES keys
  generateRsaKeypair(&localKeypair);
  generateAesKey(&aesKey, &aesIv);

  return SUCCESS;
}

int Crypto::generateRsaKeypair(EVP_PKEY **keypair) {
  EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);

  if(EVP_PKEY_keygen_init(context) <= 0) {
    return FAILURE;
  }

  if(EVP_PKEY_CTX_set_rsa_keygen_bits(context, RSA_KEYLEN) <= 0) {
    return FAILURE;
  }

  if(EVP_PKEY_keygen(context, keypair) <= 0) {
    return FAILURE;
  }

  EVP_PKEY_CTX_free(context);

  return SUCCESS;
}

int Crypto::generateAesKey(unsigned char **aesKey, unsigned char **aesIv) {
  *aesKey = (unsigned char*)malloc(AES_KEYLEN/8);
  *aesIv = (unsigned char*)malloc(AES_KEYLEN/8);

  if(aesKey == NULL || aesIv == NULL) {
    return FAILURE;
  }

  // For the AES key we have the option of using a PBKDF or just using straight random
  // data for the key and IV. Depending on your use case, you will want to pick one or another.
  #ifdef USE_PBKDF
    unsigned char *aesPass = (unsigned char*)malloc(AES_KEYLEN/8);
    unsigned char *aesSalt = (unsigned char*)malloc(8);

    if(aesPass == NULL || aesSalt == NULL) {
      return FAILURE;
    }

    // Get some random data to use as the AES pass and salt
    if(RAND_bytes(aesPass, AES_KEYLEN/8) == 0) {
      return FAILURE;
    }

    if(RAND_bytes(aesSalt, 8) == 0) {
      return FAILURE;
    }

    if(EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), aesSalt, aesPass, AES_KEYLEN/8, AES_ROUNDS, aesKey, aesIv) == 0) {
      return FAILURE;
    }

    free(aesPass);
    free(aesSalt);
  #else
    if(RAND_bytes(*aesKey, AES_KEYLEN/8) == 0) {
      return FAILURE;
    }

    if(RAND_bytes(*aesIv, AES_KEYLEN/8) == 0) {
      return FAILURE;
    }
  #endif

  return SUCCESS;
}

int Crypto::rsaEncrypt(const unsigned char *message, size_t messageLength, unsigned char **encryptedMessage, unsigned char **encryptedKey,
  size_t *encryptedKeyLength, unsigned char **iv, size_t *ivLength) {

  // Allocate memory for everything
  size_t encryptedMessageLength = 0;
  size_t blockLength = 0;

  *encryptedKey = (unsigned char*)malloc(EVP_PKEY_size(remotePublicKey));
  *iv = (unsigned char*)malloc(EVP_MAX_IV_LENGTH);
  *ivLength = EVP_MAX_IV_LENGTH;

  if(*encryptedKey == NULL || *iv == NULL) {
    return FAILURE;
  }

  *encryptedMessage = (unsigned char*)malloc(messageLength + EVP_MAX_IV_LENGTH);
  if(encryptedMessage == NULL) {
    return FAILURE;
  }

  // Encrypt it!
  if(!EVP_SealInit(rsaEncryptContext, EVP_aes_256_cbc(), encryptedKey, (int*)encryptedKeyLength, *iv, &remotePublicKey, 1)) {
    return FAILURE;
  }

  if(!EVP_SealUpdate(rsaEncryptContext, *encryptedMessage + encryptedMessageLength, (int*)&blockLength, (const unsigned char*)message, (int)messageLength)) {
    return FAILURE;
  }
  encryptedMessageLength += blockLength;

  if(!EVP_SealFinal(rsaEncryptContext, *encryptedMessage + encryptedMessageLength, (int*)&blockLength)) {
    return FAILURE;
  }
  encryptedMessageLength += blockLength;

  return (int)encryptedMessageLength;
}

int Crypto::rsaDecrypt(unsigned char *encryptedMessage, size_t encryptedMessageLength, unsigned char *encryptedKey,
  size_t encryptedKeyLength, unsigned char *iv, size_t ivLength, unsigned char **decryptedMessage) {

  // Allocate memory for everything
  size_t decryptedMessageLength = 0;
  size_t blockLength = 0;

  *decryptedMessage = (unsigned char*)malloc(encryptedMessageLength + ivLength);
  if(*decryptedMessage == NULL) {
    return FAILURE;
  }

  #ifdef PSEUDO_CLIENT
    EVP_PKEY *key = remotePublicKey;
  #else
    EVP_PKEY *key = localKeypair;
  #endif

  // Decrypt it!
  if(!EVP_OpenInit(rsaDecryptContext, EVP_aes_256_cbc(), encryptedKey, encryptedKeyLength, iv, key)) {
    return FAILURE;
  }

  if(!EVP_OpenUpdate(rsaDecryptContext, (unsigned char*)*decryptedMessage + decryptedMessageLength, (int*)&blockLength, encryptedMessage, (int)encryptedMessageLength)) {
    return FAILURE;
  }
  decryptedMessageLength += blockLength;

  if(!EVP_OpenFinal(rsaDecryptContext, (unsigned char*)*decryptedMessage + decryptedMessageLength, (int*)&blockLength)) {
    return FAILURE;
  }
  decryptedMessageLength += blockLength;

  return (int)decryptedMessageLength;
}

int Crypto::aesEncrypt(const unsigned char *message, size_t messageLength, unsigned char **encryptedMessage) {
  // Allocate memory for everything
  size_t blockLength = 0;
  size_t encryptedMessageLength = 0;

  *encryptedMessage = (unsigned char*)malloc(messageLength + AES_BLOCK_SIZE);
  if(encryptedMessage == NULL) {
    return FAILURE;
  }

  // Encrypt it!
  if(!EVP_EncryptInit_ex(aesEncryptContext, EVP_aes_256_cbc(), NULL, aesKey, aesIv)) {
    return FAILURE;
  }

  if(!EVP_EncryptUpdate(aesEncryptContext, *encryptedMessage, (int*)&blockLength, (unsigned char*)message, messageLength)) {
    return FAILURE;
  }
  encryptedMessageLength += blockLength;

  if(!EVP_EncryptFinal_ex(aesEncryptContext, *encryptedMessage + encryptedMessageLength, (int*)&blockLength)) {
    return FAILURE;
  }

  return encryptedMessageLength + blockLength;
}

int Crypto::aesDecrypt(unsigned char *encryptedMessage, size_t encryptedMessageLength, unsigned char **decryptedMessage) {
  // Allocate memory for everything
  size_t decryptedMessageLength = 0;
  size_t blockLength = 0;

  *decryptedMessage = (unsigned char*)malloc(encryptedMessageLength);
  if(*decryptedMessage == NULL) {
    return FAILURE;
  }

  // Decrypt it!
  if(!EVP_DecryptInit_ex(aesDecryptContext, EVP_aes_256_cbc(), NULL, aesKey, aesIv)) {
    return FAILURE;
  }

  if(!EVP_DecryptUpdate(aesDecryptContext, (unsigned char*)*decryptedMessage, (int*)&blockLength, encryptedMessage, (int)encryptedMessageLength)) {
    return FAILURE;
  }
  decryptedMessageLength += blockLength;

  if(!EVP_DecryptFinal_ex(aesDecryptContext, (unsigned char*)*decryptedMessage + decryptedMessageLength, (int*)&blockLength)) {
    return FAILURE;
  }
  decryptedMessageLength += blockLength;

  return (int)decryptedMessageLength;
}

int Crypto::getRemotePublicKey(unsigned char **publicKey) {
  BIO *bio = BIO_new(BIO_s_mem());
  PEM_write_bio_PUBKEY(bio, remotePublicKey);
  return bioToString(bio, publicKey);
}

int Crypto::setRemotePublicKey(unsigned char *publicKey, size_t publicKeyLength) {
  BIO *bio = BIO_new(BIO_s_mem());

  if(BIO_write(bio, publicKey, publicKeyLength) != (int)publicKeyLength) {
    return FAILURE;
  }

  PEM_read_bio_PUBKEY(bio, &remotePublicKey, NULL, NULL);
  BIO_free_all(bio);

  return SUCCESS;
}

int Crypto::getLocalPublicKey(unsigned char **publicKey) {
  BIO *bio = BIO_new(BIO_s_mem());
  PEM_write_bio_PUBKEY(bio, localKeypair);
  return bioToString(bio, publicKey);
}

int Crypto::getLocalPrivateKey(unsigned char **privateKey) {
  BIO *bio = BIO_new(BIO_s_mem());
  PEM_write_bio_PrivateKey(bio, localKeypair, NULL, NULL, 0, 0, NULL);
  return bioToString(bio, privateKey);
}

int Crypto::getAesKey(unsigned char **aesKey) {
  *aesKey = this->aesKey;
  return AES_KEYLEN/8;
}

int Crypto::setAesKey(unsigned char *aesKey, size_t aesKeyLength) {
  // Ensure the new key is the proper size
  if((int)aesKeyLength != AES_KEYLEN/8) {
    return FAILURE;
  }

  memcpy(this->aesKey, aesKey, AES_KEYLEN/8);

  return SUCCESS;
}

int Crypto::getAesIv(unsigned char **aesIv) {
  *aesIv = this->aesIv;
  return AES_KEYLEN/8;
}

int Crypto::setAesIv(unsigned char *aesIv, size_t aesIvLength) {
  // Ensure the new IV is the proper size
  if((int)aesIvLength != AES_KEYLEN/8) {
    return FAILURE;
  }

  memcpy(this->aesIv, aesIv, AES_KEYLEN/8);

  return SUCCESS;
}

int Crypto::writeKeyToFile(FILE *file, int key) {
  switch(key) {
    case KEY_SERVER_PRI:
      if(!PEM_write_PrivateKey(file, localKeypair, NULL, NULL, 0, 0, NULL)) {
        return FAILURE;
      }
      break;

    case KEY_SERVER_PUB:
      if(!PEM_write_PUBKEY(file, localKeypair)) {
        return FAILURE;
      }
      break;

    case KEY_CLIENT_PUB:
      if(!PEM_write_PUBKEY(file, remotePublicKey)) {
        return FAILURE;
      }
      break;

    case KEY_AES:
      fwrite(aesKey, 1, AES_KEYLEN, file);
      break;

    case KEY_AES_IV:
      fwrite(aesIv, 1, AES_KEYLEN, file);
      break;

    default:
      return FAILURE;
  }

  return SUCCESS;
}

int Crypto::bioToString(BIO *bio, unsigned char **string) {
  size_t bioLength = BIO_pending(bio);
  *string = (unsigned char*)malloc(bioLength + 1);

  if(string == NULL) {
    return FAILURE;
  }

  BIO_read(bio, *string, bioLength);

  // Insert the NUL terminator
  (*string)[bioLength] = '\0';

  BIO_free_all(bio);

  return (int)bioLength;
}
