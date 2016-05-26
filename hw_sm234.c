/*
 * hw_sm234.c
 * Originally written by Zhao Junwang<zhjwpku@gmail.com> for the cryptop 
 * safemodule.
 */

#include <string.h>
#include <openssl/evp.h>
#include <openssl/sms4.h>
#include <openssl/sm3.h>
#include <openssl/objects.h>

#include "common.h"

#if IS_CRYPTOP
extern unsigned int reg_base;

// SM3
static int my_sm3_init(EVP_MD_CTX *ctx);
static int my_sm3_update(EVP_MD_CTX *ctx, const void *data, size_t len);
static int my_sm3_final(EVP_MD_CTX *ctx, unsigned char *md);

void engine_sm3_init(EVP_MD *digest_sm3)
{
  memcpy(digest_sm3, EVP_sm3(), sizeof(EVP_MD));
  digest_sm3 -> init = my_sm3_init;
  digest_sm3 -> update = my_sm3_update;
  digest_sm3 -> final = my_sm3_final;
}

// SM4
int sm4_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
		 const unsigned char *iv, int enc);
int sm4_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
		  const unsigned char *in, size_t len);

// SM3 implementatins
static int my_sm3_init(EVP_MD_CTX *ctx)
{
  sm3_ctx_t *c = (sm3_ctx_t *)(ctx->md_data);
  c->nblocks = 0;
  c->num = 0;
  memset(c->block, 0, sizeof(c->block));

  REG_MODE = 0x10;
  return 1;
}

static void sm3_transform(const void *buffer, int last, size_t last_len)
{
  int i = 0;
  const unsigned char *p = buffer;
  for (i = 0; i < 16; i++) {
    REG_MSG(i) = GETU32(p + i * 4);
  }

  REG_HASH_PORT_HIG = 0x80000;
  if (last == 0) {
    REG_HASH_PORT_LOW = 0xf0000001;
  } else {
    REG_HASH_PORT_LOW = 0xf0004001 | (last_len << 4);
  }
}

static int my_sm3_update(EVP_MD_CTX *ctx, const void *data, size_t len)
{
  sm3_ctx_t *c = (sm3_ctx_t *)(ctx->md_data);
  const unsigned char *p = data;
  int i = 0;
  int n = len / 64;
  int m = len % 64;

  for (i = 0; i < n; i++) {
    sm3_transform(p + i*64, 0, 0);
  }

  c->nblocks += n;
  c->num = m;
  if (m > 0) {
    memcpy(c->block, p + i*64, m);
  }

  return 1;
}

static int my_sm3_final(EVP_MD_CTX *ctx, unsigned char *md)
{
  sm3_ctx_t *c = (sm3_ctx_t *)(ctx->md_data);
  unsigned char *tmp = (unsigned char *)(c->block);
  int m = c->num;
  int len = ((c->nblocks * 64) + m) << 3;
  int i = 0;
  int val;

  if (m < 56) { // the last block
    tmp[m] = 0x80;
    PUTU32(len, tmp+60);
    sm3_transform(tmp, 1, m << 3);
  } else {
    tmp[m] = 0x80;
    sm3_transform(tmp, 0, 0); // the second last
    memset(tmp, 0, sizeof(tmp));
    PUTU32(len, tmp+60);
    sm3_transform(tmp, 1, m << 3);
  }

  val = REG_HASH(0);
  for (i = 0; i < 8; i++) {
    val = REG_HASH(i);
    PUTU32(val, md + i * 4);
  }

  return 1;
}

// SM4 implementations
int sm4_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
		 const unsigned char *iv, int enc)
{
  int i;
  unsigned int mode;
  
  mode = EVP_CIPHER_CTX_mode(ctx) - 1;

  REG_MODE = 0x20;
  REG_SM4 = BC_INI(2, 0, enc, mode, 0);

  for (i = 0; i < 4; i++)
    REG_KEY(i) = GETU32(key + i * 4);

  // Key expension
  REG_SM4 = KEXP(2, 0, enc, mode, 0);
  
  if (!mode) {
    for (i = 0; i < 4; i++)
      REG_IV(i) = GETU32(iv + i * 4);
  }
  return 1;
}

int sm4_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
		  const unsigned char *in, size_t len)
{
  int block;
  int i, j;
  unsigned int mode;
  
  mode = EVP_CIPHER_CTX_mode(ctx) - 1;

  block = len / 16;

  for (i = 0; i < block; i++) {
    for (j = 0; j < 4; j++) {
      REG_TEXT(j) = GETU32(in + i*16 + j*4);
    }

    REG_SM4 = ED(2, 0, ctx->encrypt, mode, 0, 0);
    int a[5];
    a[4] = REG_RESULT(0);
    a[3] = REG_RESULT(1);
    for (j = 0; j < 4; j++) {
      a[j] = REG_RESULT(j);
    }

    for (j = 0; j < 4; j++) {
      PUTU32(a[j], out + 16*i + j*4);
    }
  }

  return 1;
}

#endif
