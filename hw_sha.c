/*
 * hw_sha.c
 * Originally written by Zhao Junwang<zhjwpku@gmail.com> for the cryptop 
 * safemodule.
 * This project implements a engine accelerate the following algorithms:
 */

#include <openssl/evp.h>
#include <string.h>
#include <openssl/sha.h>
#include <stdio.h>
#include "common.h"

#if IS_CRYPTOP
extern unsigned int reg_base;
#endif
extern unsigned int fd;

// SHA1, namely SHA160
static int sha1_init(EVP_MD_CTX *ctx);
static int sha1_update(EVP_MD_CTX *ctx, const void *data, size_t len);
static int sha1_final(EVP_MD_CTX *ctx, unsigned char *md);

static int sha256_init(EVP_MD_CTX *ctx);
static int sha256_update(EVP_MD_CTX *ctx, const void *data, size_t len);
static int sha256_final(EVP_MD_CTX *ctx, unsigned char *md);

// The engine calls this function to initial EVP_MD sha1
void engine_sha1_init(EVP_MD * digest_sha1)
{
  memcpy(digest_sha1, EVP_sha1(), sizeof(EVP_MD));

#if IS_CRYPTOP  
  digest_sha1->init = sha1_init;
  digest_sha1->update = sha1_update;
  digest_sha1->final = sha1_final;
#endif
}

// The engine calls this function to initial EVP_MD sha256
void engine_sha256_init(EVP_MD * digest_sha256)
{
  memcpy(digest_sha256, EVP_sha256(), sizeof(EVP_MD));

#if IS_CRYPTOP  
  digest_sha256->init = sha256_init;
  digest_sha256->update = sha256_update;
  digest_sha256->final = sha256_final;
#endif  
}

#if IS_CRYPTOP
// The sha1 implementatitons
static int sha1_init(EVP_MD_CTX *ctx)
{
  SHA_CTX *c = (SHA_CTX *)(ctx->md_data);
  c->Nl = 0;
  c->Nh = 0;
  memset(c->data, 0, sizeof(c->data));

  REG_MODE = 0x10;
  return 1;
}

/* Hash a single 512-bit block. This is the core of the algorithm */
static void sha1_transform(const void *buffer, int last, size_t last_len)
{
  int i = 0;
  unsigned int tmp;
  const unsigned char *p = buffer;
  for(i = 0; i < 16; i++) {
    tmp = (p[i*4] << 24) + (p[i*4+1] << 16) + (p[i*4+2] << 8) + p[i*4+3];
    REG_MSG(i) = tmp;
  }

  if (last == 0) {	// not the last one
    REG_HASH_PORT_HIG = 0x80000;
    REG_HASH_PORT_LOW = 0xf0000009;
  } else {	// the last one
    REG_HASH_PORT_HIG = 0x80000;
    REG_HASH_PORT_LOW = 0xf0004009 | (last_len << 4);
    usleep(1);
  }
}

static int sha1_update(EVP_MD_CTX *ctx, const void *data, size_t len)
{
  SHA_CTX *c = (SHA_CTX *)(ctx->md_data);
  const unsigned char *p = data;
  int i = 0;
  int n = len / 64;
  int m = len % 64;

  for (i = 0; i < n; i++) {
    sha1_transform(p + i*64, 0, 0);
  }

  c->Nl = m;
  c->Nh = len;
  if (m > 0) {
    memcpy(c->data, p + i*64, m);
  }

  return 1;
}

static int sha1_final(EVP_MD_CTX *ctx, unsigned char *md)
{
  SHA_CTX *c = (SHA_CTX *)(ctx->md_data);
  unsigned char *tmp = (unsigned char *)(c->data);
  int m = c->Nl;
  int len = c->Nh;
  int i = 0;
  int val;

  if (m < 56) {
    tmp[m] = 0x80;
    
    tmp[60] = ((len << 3) >> 24) & 0xff;
    tmp[61] = ((len << 3) >> 16) & 0xff;
    tmp[62] = ((len << 3) >> 8 ) & 0xff;
    tmp[63] = ((len << 3)        & 0xff);
    sha1_transform(tmp, 1, m << 3);	// the last one
  } else {
    tmp[m] = 0x80;
    sha1_transform(tmp, 0, 0);	// not the last one
    memset(tmp, 0, sizeof(tmp));
    
    tmp[60] = ((len << 3) >> 24) & 0xff;
    tmp[61] = ((len << 3) >> 16) & 0xff;
    tmp[62] = ((len << 3) >> 8 ) & 0xff;
    tmp[63] = ((len << 3)        & 0xff);
    sha1_transform(tmp, 1, 0);	// the last one
  }

  for (i = 0; i < 5; i++) {
    val = REG_HASH(i);
    md[i*4] =   (val >> 24) & 0xff;
    md[i*4+1] = (val >> 16) & 0xff;
    md[i*4+2] = (val >> 8 ) & 0xff;
    md[i*4+3] = (val      ) & 0xff;
  }

  return 1;
}

// The sha256 implementatitons
static int sha256_init(EVP_MD_CTX *ctx)
{
  SHA256_CTX *c = (SHA256_CTX *)(ctx->md_data);
  c->Nl = 0;
  c->Nh = 0;
  memset(c->data, 0, sizeof(c->data));
  
  REG_MODE = 0x10;

  return 1;
}

static void sha256_transform(const void *buffer, int last, size_t last_len)
{
  int i = 0;
  unsigned int tmp;
  const unsigned char *p = buffer;
  for (i = 0; i < 16; i++) {
    tmp = (p[i*4] << 24) + (p[i*4+1] << 16) + (p[i*4+2] << 8) + p[i*4+3];
    REG_MSG(i) = tmp;
  }

  if (last == 0) {
    REG_HASH_PORT_HIG = 0x80000;
    REG_HASH_PORT_LOW = 0xf0000005;
  } else {
    REG_HASH_PORT_HIG = 0x80000;
    REG_HASH_PORT_LOW = 0xf0004005 | (last_len << 4);
    usleep(1);
  }
}

static int sha256_update(EVP_MD_CTX *ctx, const void *data, size_t len)
{
  SHA256_CTX *c = (SHA256_CTX *)(ctx->md_data);
  const unsigned char *p = data;
  int i = 0;
  int n = len / 64;
  int m = len % 64;

  for (i = 0; i < n; i++) {
    sha256_transform(p + i*64, 0, 0);
  }

  c->Nl = m;
  c->Nh = len;
  if (m > 0) {
    memcpy(c->data, p + i*64, m);
  }

  return 1;
}

static int sha256_final(EVP_MD_CTX *ctx, unsigned char *md)
{
  SHA256_CTX *c = (SHA256_CTX *)(ctx->md_data);
  unsigned char *tmp = (unsigned char *)(c->data);
  int m = c->Nl;
  int len = c->Nh;
  int i = 0;
  int val;

  if (m < 56) { // the last block
    tmp[m] = 0x80;
    tmp[60] = ((len << 3) >> 24) & 0xff;
    tmp[61] = ((len << 3) >> 16) & 0xff;
    tmp[62] = ((len << 3) >> 8 ) & 0xff;
    tmp[63] = ((len << 3)        & 0xff);
    sha256_transform(tmp, 1, m << 3);
  } else {
    tmp[m] = 0x80;
    sha256_transform(tmp, 0, 0); // the second last
    memset(tmp, 0, sizeof(tmp));
    tmp[60] = ((len << 3) >> 24) & 0xff;
    tmp[61] = ((len << 3) >> 16) & 0xff;
    tmp[62] = ((len << 3) >> 8 ) & 0xff;
    tmp[63] = ((len << 3)        & 0xff);
    sha256_transform(tmp, 1, m << 3);
  }

  for (i = 0; i < 8; i++) {
    val = REG_HASH(i);
    md[i*4] =   (val >> 24) & 0xff;
    md[i*4+1] = (val >> 16) & 0xff;
    md[i*4+2] = (val >> 8 ) & 0xff;
    md[i*4+3] = (val      ) & 0xff;
  }

  return 1;
}
#endif
