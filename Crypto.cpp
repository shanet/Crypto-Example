#include "Crypto.h"

EVP_PKEY* Crypto::localKeypair;

Crypto::Crypto() {
  localKeypair = nullptr;
  remotePublicKey = nullptr;

  #ifdef PSEUDO_CLIENT
    generateRsaKeypair(&remotePublicKey);
  #endif

  init();
}

Crypto::Crypto(unsigned char *remotePublicKey, size_t remotePublicKeyLength) {
  localKeypair = nullptr;
  this->remotePublicKey = nullptr;

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
  if(rsaEncryptContext == nullptr || aesEncryptContext == nullptr || rsaDecryptContext == nullptr || aesDecryptContext == nullptr) {
    return FAILURE;
  }

  /* Don't set key or IV right away; we want to set lengths */
  EVP_CIPHER_CTX_init(aesEncryptContext);
  EVP_CIPHER_CTX_init(aesDecryptContext);

  EVP_CipherInit_ex(aesEncryptContext, EVP_aes_256_cbc(), nullptr, nullptr, nullptr, 1);

  /* Now we can set key and IV lengths */
  aesKeyLength = EVP_CIPHER_CTX_key_length(aesEncryptContext);
  aesIvLength = EVP_CIPHER_CTX_iv_length(aesEncryptContext);

  // Generate RSA and AES keys
  generateRsaKeypair(&localKeypair);
  generateAesKey(&aesKey, &aesIv);

  return SUCCESS;
}

int Crypto::generateRsaKeypair(EVP_PKEY **keypair) {
  EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);

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
  *aesKey = static_cast<unsigned char*>(std::malloc(aesKeyLength));
  *aesIv = static_cast<unsigned char*>(std::malloc(aesIvLength));

  if(*aesKey == nullptr || *aesIv == nullptr) {
    return FAILURE;
  }

  // For the AES key we have the option of using a PBKDF or just using straight random
  // data for the key and IV. Depending on your use case, you will want to pick one or another.
  #ifdef USE_PBKDF
    unsigned char *aesPass = static_cast<unsigned char*>(std::malloc(aesKeyLength));
    unsigned char *aesSalt = static_cast<unsigned char*>(std::malloc(8));

    if((*aesPass == nullptr) || (*aesSalt == nullptr)) {
      if (nullptr != *aesPass){
        free(aesPass);
      }
      if (nullptr != *aesSalt){
        free(aesSalt);
      }
      return FAILURE;
    }

    // Get some random data to use as the AES pass and salt
    if(RAND_bytes(aesPass, aesKeyLength) == 0) {
      free(aesSalt);
      free(aesPass);
      return FAILURE;
    }

    if(RAND_bytes(aesSalt, 8) == 0) {
      free(aesSalt);
      free(aesPass);
      return FAILURE;
    }

    if(EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), aesSalt, aesPass, aesKeyLength, AES_ROUNDS, aesKey, aesIv) == 0) {
      free(aesSalt);
      free(aesPass);
      return FAILURE;
    }
  #else
    if(RAND_bytes(*aesKey, aesKeyLength) == 0) {
      return FAILURE;
    }

    if(RAND_bytes(*aesIv, aesIvLength) == 0) {
      return FAILURE;
    }
  #endif

  return SUCCESS;
}

int Crypto::rsaEncrypt(const unsigned char *message, size_t messageLength, unsigned char **encryptedMessage, unsigned char **encryptedKey,
  int *encryptedKeyLength, unsigned char **iv, int *ivLength) {

  // Allocate memory for everything
  size_t encryptedMessageLength = 0;
  int blockLength = 0;

  *encryptedKey = static_cast<unsigned char*>(std::malloc(EVP_PKEY_size(remotePublicKey)));
  *iv = static_cast<unsigned char*>(std::malloc(EVP_MAX_IV_LENGTH));
  *ivLength = EVP_MAX_IV_LENGTH;

  if(*encryptedKey == nullptr || *iv == nullptr) {
    return FAILURE;
  }

  *encryptedMessage = static_cast<unsigned char*>(std::malloc(messageLength + EVP_MAX_IV_LENGTH));
  if(*encryptedMessage == nullptr) {
    return FAILURE;
  }

  // Encrypt it!
  if(!EVP_SealInit(rsaEncryptContext, EVP_aes_256_cbc(), encryptedKey, encryptedKeyLength, *iv, &remotePublicKey, 1)) {
    return FAILURE;
  }

  if(!EVP_SealUpdate(rsaEncryptContext, *encryptedMessage + encryptedMessageLength, &blockLength, message, static_cast<int>(messageLength))) {
    return FAILURE;
  }
  encryptedMessageLength += blockLength;

  if(!EVP_SealFinal(rsaEncryptContext, *encryptedMessage + encryptedMessageLength, reinterpret_cast<int*>(&blockLength))) {
    return FAILURE;
  }
  encryptedMessageLength += blockLength;

  return static_cast<int>(encryptedMessageLength);
}

int Crypto::rsaDecrypt(unsigned char *encryptedMessage, size_t encryptedMessageLength, unsigned char *encryptedKey,
  size_t encryptedKeyLength, unsigned char *iv, size_t ivLength, unsigned char **decryptedMessage) {

  // Allocate memory for everything
  size_t decryptedMessageLength = 0;
  size_t blockLength = 0;

  *decryptedMessage = static_cast<unsigned char*>(std::malloc(encryptedMessageLength + ivLength));
  if(*decryptedMessage == nullptr) {
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

  if(!EVP_OpenUpdate(rsaDecryptContext, (unsigned char*)*decryptedMessage + decryptedMessageLength, reinterpret_cast<int*>(&blockLength), encryptedMessage, static_cast<int>(encryptedMessageLength))) {
    return FAILURE;
  }
  decryptedMessageLength += blockLength;

  if(!EVP_OpenFinal(rsaDecryptContext, (unsigned char*)*decryptedMessage + decryptedMessageLength, reinterpret_cast<int*>(&blockLength))) {
    return FAILURE;
  }
  decryptedMessageLength += blockLength;

  return static_cast<int>(decryptedMessageLength);
}

int Crypto::aesEncrypt(const unsigned char *message, size_t messageLength, unsigned char **encryptedMessage) {
  // Allocate memory for everything
  size_t blockLength = 0;
  size_t encryptedMessageLength = 0;

  *encryptedMessage = static_cast<unsigned char*>(std::malloc(messageLength + AES_BLOCK_SIZE));
  if(*encryptedMessage == nullptr) {
    return FAILURE;
  }

  // Encrypt it!
  if(!EVP_EncryptInit_ex(aesEncryptContext, EVP_aes_256_cbc(), nullptr, aesKey, aesIv)) {
    return FAILURE;
  }

  if(!EVP_EncryptUpdate(aesEncryptContext, *encryptedMessage, reinterpret_cast<int*>(&blockLength), (unsigned char*)message, messageLength)) {
    return FAILURE;
  }
  encryptedMessageLength += blockLength;

  if(!EVP_EncryptFinal_ex(aesEncryptContext, *encryptedMessage + encryptedMessageLength, reinterpret_cast<int*>(&blockLength))) {
    return FAILURE;
  }

  return encryptedMessageLength + blockLength;
}

int Crypto::aesDecrypt(unsigned char *encryptedMessage, size_t encryptedMessageLength, unsigned char **decryptedMessage) {
  // Allocate memory for everything
  size_t decryptedMessageLength = 0;
  size_t blockLength = 0;

  *decryptedMessage = static_cast<unsigned char*>(std::malloc(encryptedMessageLength));
  if(*decryptedMessage == nullptr) {
    return FAILURE;
  }

  // Decrypt it!
  if(!EVP_DecryptInit_ex(aesDecryptContext, EVP_aes_256_cbc(), nullptr, aesKey, aesIv)) {
    return FAILURE;
  }

  if(!EVP_DecryptUpdate(aesDecryptContext, (unsigned char*)*decryptedMessage, reinterpret_cast<int*>(&blockLength), encryptedMessage, static_cast<int>(encryptedMessageLength))) {
    return FAILURE;
  }
  decryptedMessageLength += blockLength;

  if(!EVP_DecryptFinal_ex(aesDecryptContext, (unsigned char*)*decryptedMessage + decryptedMessageLength, reinterpret_cast<int*>(&blockLength))) {
    return FAILURE;
  }
  decryptedMessageLength += blockLength;

  return static_cast<int>(decryptedMessageLength);
}

int Crypto::getRemotePublicKey(unsigned char **publicKey) {
  BIO *bio = BIO_new(BIO_s_mem());
  PEM_write_bio_PUBKEY(bio, remotePublicKey);
  return bioToString(bio, publicKey);
}

int Crypto::setRemotePublicKey(unsigned char *publicKey, size_t publicKeyLength) {
  BIO *bio = BIO_new(BIO_s_mem());

  if(BIO_write(bio, publicKey, publicKeyLength) != static_cast<int>(publicKeyLength)) {
    return FAILURE;
  }

  PEM_read_bio_PUBKEY(bio, &remotePublicKey, nullptr, nullptr);
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
  PEM_write_bio_PrivateKey(bio, localKeypair, nullptr, nullptr, 0, 0, nullptr);
  return bioToString(bio, privateKey);
}

int Crypto::getAesKey(unsigned char **aesKey) {
  *aesKey = this->aesKey;
  return aesKeyLength;
}

int Crypto::setAesKey(unsigned char *aesKey, size_t aesKeyLengthgth) {
  // Ensure the new key is the proper size
  if(aesKeyLengthgth != aesKeyLength) {
    return FAILURE;
  }

  memcpy(this->aesKey, aesKey, aesKeyLength);

  return SUCCESS;
}

int Crypto::getAesIv(unsigned char **aesIv) {
  *aesIv = this->aesIv;
  return aesIvLength;
}

int Crypto::setAesIv(unsigned char *aesIv, size_t aesIvLengthgth) {
  // Ensure the new IV is the proper size
  if(aesIvLengthgth != aesIvLength) {
    return FAILURE;
  }

  memcpy(this->aesIv, aesIv, aesIvLength);

  return SUCCESS;
}

int Crypto::writeKeyToFile(FILE *file, int key) {
  switch(key) {
    case KEY_SERVER_PRI:
      if(!PEM_write_PrivateKey(file, localKeypair, nullptr, nullptr, 0, 0, nullptr)) {
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
      fwrite(aesKey, 1, aesKeyLength * 8, file);
      break;

    case KEY_AES_IV:
      fwrite(aesIv, 1, aesIvLength * 8, file);
      break;

    default:
      return FAILURE;
  }

  return SUCCESS;
}

int Crypto::bioToString(BIO *bio, unsigned char **string) {
  size_t bioLength = BIO_pending(bio);
  *string = static_cast<unsigned char*>(std::malloc(bioLength + 1));

  if(*string == nullptr) {
    return FAILURE;
  }

  BIO_read(bio, *string, bioLength);

  // Insert the NUL terminator
  (*string)[bioLength] = '\0';

  BIO_free_all(bio);

  return static_cast<int>(bioLength);
}
