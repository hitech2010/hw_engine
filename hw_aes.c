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
  AES_Cipher_Data *dat = (AES_Cipher_Data *)(ctx->cipher_data);
  
  dat->mode = mode;
  dat->enc = enc;

  mode = EVP_CIPHER_CTX_mode(ctx) - 1;

  REG_MODE = 0x20;
  switch (ctx->key_len) {
  case 16:
    key_len = 0;
    break;
  case 24:
    key_len = 1;
    break;
  case 32:
    key_len = 2;
    break;
  default:
    key_len = 0;
    break;
  }

  dat->key_len = key_len;

  REG_AES = BC_INI(0, key_len, enc, mode, 0);

  for (i = 0; i < (4 + key_len * 2); i++)
    REG_KEY(i) = GETU32(key + i * 4);

  // Key expension
  REG_AES = KEXP(0, key_len, enc, mode, 0);
  
  if (!mode) {
    for (i = 0; i < 4; i++)
      REG_IV(i) = GETU32(iv + i * 4);
  }
  return 1;
}

int aes_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
			  const unsigned char *in, size_t len)
{
  int block;
  int last;
  int i, j;
  unsigned int tmp;
  int q = 0;
  AES_Cipher_Data *dat = (AES_Cipher_Data *)(ctx->cipher_data);

  block = len / 16;

  for (i = 0; i < block; i++) {
    for (j = 0; j < 4; j++) {
      tmp = (in[i*16 + j*4] << 24) + (in[i*16+j*4 + 1] << 16) \
      + (in[i*16+j*4+2] << 8) | (in[i*16+j*4+3]);
      REG_TEXT(j) = tmp;
    }

    REG_AES = ED(0, dat->key_len, dat->enc, dat->mode, 0, 0);
    
    int a[5];
    a[4] = REG_RESULT(0);
    for (j = 0; j < 4; j++) {
      a[j] = REG_RESULT(j);
    }

    for (j = 0; j < 4; j++) {
      out[i*16+j*4 + 3] = a[j] & 0xff;
      out[i*16+j*4 + 2] = (a[j] >> 8)  & 0xff;
      out[i*16+j*4 + 1] = (a[j] >> 16) & 0xff;
      out[i*16+j*4 + 0] = (a[j] >> 24) & 0xff;
    }
  }

  return 1;
}
#endif
