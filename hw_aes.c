#include <openssl/evp.h>
#include <string.h>
#include <openssl/md5.h>

#include "common.h"

static int aes_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
			const unsigned char *iv, int enc);
static int aes_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
			const unsigned char *in, size_t inl);

// The engine calls this function to initial EVP_CIPHER
void engine_cipher_init(EVP_CIPHER *cipher, int type)
{
  switch (type) {
    case HW_AES_128_ECB:
      memcpy(cipher, EVP_aes_128_ecb(), sizeof(EVP_CIPHER));
      break;
    case HW_AES_128_CBC:
      memcpy(cipher, EVP_aes_128_cbc(), sizeof(EVP_CIPHER));
      break;
    case HW_AES_128_CFB:
      memcpy(cipher, EVP_aes_128_cfb(), sizeof(EVP_CIPHER));
      break;
    case HW_AES_128_OFB:
      memcpy(cipher, EVP_aes_128_ofb(), sizeof(EVP_CIPHER));
      break;
    default:
      return;
  }
}

// The implementatitons
static int aes_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
			const unsigned char *iv, int enc)
{
  return 1;
}
static int aes_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
			const unsigned char *in, size_t inl)
{
  return 1;
}
