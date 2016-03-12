/*
 * hw_aes.c
 * Originally written by Zhao Junwang<zhjwpku@gmail.com> for the cryptop 
 * safemodule.
 */

#include <string.h>

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/modes.h>

int aes_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
			const unsigned char *iv, int enc)
{
  return 1;
}

int aes_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
			  const unsigned char *in, size_t len)
{
  return 1;
}

int aes_ecb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
			  const unsigned char *in, size_t len)
{
  return 1;
}

int aes_cfb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
			  const unsigned char *in, size_t len)
{
  return 1;
}

int aes_ofb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
			  const unsigned char *in, size_t len)
{
  return 1;
}

int aes_ctr_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
			  const unsigned char *in, size_t len)
{
  return 1;
}
