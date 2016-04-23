/*
 * hw_aes.c
 * Originally written by Zhao Junwang<zhjwpku@gmail.com> for the cryptop 
 * safemodule.
 */

#include <string.h>

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/modes.h>

#include "common.h"

#if IS_CRYPTOP
extern unsigned int reg_base;

int aes_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
			const unsigned char *iv, int enc)
{
  int i;
  unsigned int key_len, mode;

  mode = EVP_CIPHER_CTX_mode(ctx) - 1;
  key_len = (ctx->key_len)/8 - 2;

  REG_MODE = 0x20;

  REG_AES = BC_INI(0, key_len, enc, mode, 0);

  for (i = 0; i < (4 + key_len * 2); i++)
    REG_KEY(i) = GETU32(key + i * 4);

  if (!mode) {
    for (i = 0; i < 4; i++)
      REG_IV(i) = GETU32(iv + i * 4);
  }

  // Key expension
  REG_AES = KEXP(0, key_len, enc, mode, 0);
  
  return 1;
}

int aes_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
			  const unsigned char *in, size_t len)
{
  int block;
  int i, j;
  unsigned int mode, key_len;

  mode = EVP_CIPHER_CTX_mode(ctx) - 1;
  key_len = (ctx->key_len)/8 - 2;

  block = len / 16;

  for (i = 0; i < block; i++) {
    for (j = 0; j < 4; j++) {
      REG_TEXT(j) = GETU32(in + i*16 + j*4);
    }

    REG_AES = ED(0, key_len, ctx->encrypt, mode, 0, 0);
    
    int a[5];
    a[4] = REG_RESULT(0);
    for (j = 0; j < 4; j++) {
      a[j] = REG_RESULT(j);
    }

    for (j = 0; j < 4; j++) {
      PUTU32(a[j], out + i*16 + j*4);
    }
  }

  return 1;
}
#endif
