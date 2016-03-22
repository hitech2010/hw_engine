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
static int sm4_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc);

void sm4_init(EVP_CIPHER *sm4_cipher, int mode)
{
  switch (mode) {
  case SM4_ECB:
    memcpy(sm4_cipher, EVP_sms4_ecb(), sizeof(EVP_CIPHER));
    // TODO: change the default implementation
    break;
  case SM4_CBC:
    memcpy(sm4_cipher, EVP_sms4_cbc(), sizeof(EVP_CIPHER));
    break;
  case SM4_CFB:
    memcpy(sm4_cipher, EVP_sms4_cfb128(), sizeof(EVP_CIPHER));
    break;
  }
}

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
  unsigned int tmp;
  const unsigned char *p = buffer;
  for (i = 0; i < 16; i++) {
    tmp = (p[i*4] << 24) + (p[i*4+1] << 16) + (p[i*4+2] << 8) + p[i*4+3];
    *(unsigned int *)(reg_base + 0x9e4 + i*4) = tmp;
  }

  if (last == 0) {
    *(unsigned int *)(reg_base + 0x988) = 0x80000;
    *(unsigned int *)(reg_base + 0x984) = 0xf0000001;
  } else {
    *(unsigned int *)(reg_base + 0x988) = 0x80000;
    *(unsigned int *)(reg_base + 0x984) = 0xf0004001 | (last_len << 4);
    usleep(1);
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

  c->nblocks = m;
  c->num = len;
  if (m > 0) {
    memcpy(c->block, p + i*64, m);
  }

  return 1;
}

static int my_sm3_final(EVP_MD_CTX *ctx, unsigned char *md)
{
  sm3_ctx_t *c = (sm3_ctx_t *)(ctx->md_data);
  unsigned char *tmp = (unsigned char *)(c->block);
  int m = c->nblocks;
  int len = c->num;
  int i = 0;
  int val;

  if (m < 56) { // the last block
    tmp[m] = 0x80;
    tmp[60] = ((len << 3) & 0xff000000) >> 24;
    tmp[61] = ((len << 3) & 0x00ff0000) >> 16;
    tmp[62] = ((len << 3) & 0x0000ff00) >> 8;
    tmp[63] = ((len << 3) & 0x000000ff);
    sm3_transform(tmp, 1, m << 3);
  } else {
    tmp[m] = 0x80;
    sm3_transform(tmp, 0, 0); // the second last
    memset(tmp, 0, sizeof(tmp));
    tmp[60] = ((len << 3) & 0xff000000) >> 24;
    tmp[61] = ((len << 3) & 0x00ff0000) >> 16;
    tmp[62] = ((len << 3) & 0x0000ff00) >> 8;
    tmp[63] = ((len << 3) & 0x000000ff);
    sm3_transform(tmp, 1, m << 3);
  }

  for (i = 0; i < 8; i++) {
    val = *(unsigned int *)(reg_base + 0xa24 + i*4);
    md[i*4] = (val & 0xff000000) >> 24;
    md[i*4+1] = (val & 0x00ff0000) >> 16;
    md[i*4+2] = (val & 0x0000ff00) >> 8;
    md[i*4+3] = (val & 0x000000ff);
  }

  return 1;
}

#endif
