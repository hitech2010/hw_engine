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

extern unsigned int reg_base;
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
  digest_sha1->init = sha1_init;
  digest_sha1->update = sha1_update;
  digest_sha1->final = sha1_final;
}

// The engine calls this function to initial EVP_MD sha256
void engine_sha256_init(EVP_MD * digest_sha256)
{
  memcpy(digest_sha256, EVP_sha256(), sizeof(EVP_MD));
  digest_sha256->init = sha256_init;
  digest_sha256->update = sha256_update;
  digest_sha256->final = sha256_final;
}

// The sha1 implementatitons
static int sha1_init(EVP_MD_CTX *ctx)
{
  SHA_CTX *c = (SHA_CTX *)(ctx->md_data);
  c->Nl = 0;
  c->Nh = 0;
  memset(c->data, 0, sizeof(c->data));

  *(unsigned int *)(reg_base + 0x920) = 0x10;
  return 1;
}

/* Hash a single 512-bit block. This is the core of the algorithm */
static void sha1_transform(const void *buffer, int last, size_t last_len)
{
  int i = 0;
  const unsigned int *p = buffer;
  for(i = 0; i < 16; i++) {
    *(unsigned int *)(reg_base + 0x9e4 + i*4) = p[i];
  }

  if (last == 0) {	// not the last one
    *(unsigned int *)(reg_base + 0x988) = 0x80000;
    *(unsigned int *)(reg_base + 0x984) = 0xf0000009;
  } else {	// the last one
    *(unsigned int *)(reg_base + 0x988) = 0x80000;
    *(unsigned int *)(reg_base + 0x984) = 0xf0004009 | (last_len << 4);
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
  unsigned int *md_p = (unsigned int *)md;
  int m = c->Nl;
  int len = c->Nh;
  int i = 0;
  int val;

  if (m < 56) {
    tmp[m] = 0x80;
    
    tmp[60] = ((len << 3) & 0xff000000) >> 24;
    tmp[61] = ((len << 3) & 0x00ff0000) >> 16;
    tmp[62] = ((len << 3) & 0x0000ff00) >> 8;
    tmp[63] = ((len << 3) & 0x000000ff);
    sha1_transform(tmp, 1, m << 3);	// the last one
  } else {
    tmp[m] = 0x80;
    sha1_transform(tmp, 0, 0);	// not the last one
    memset(tmp, 0, sizeof(tmp));
    
    tmp[60] = ((len << 3) & 0xff000000) >> 24;
    tmp[61] = ((len << 3) & 0x00ff0000) >> 16;
    tmp[62] = ((len << 3) & 0x0000ff00) >> 8;
    tmp[63] = ((len << 3) & 0x000000ff);
    sha1_transform(tmp, 1, 0);	// the last one
  }
/*
  // This is different from SHA256's big endian
  for (i = 0; i < 5; i++) {
    md_p[i] = *(unsigned int *)(reg_base + 0xa24 + i*4);
  }
*/

  for (i = 0; i < 5; i++) {
    val = *(unsigned int *)(reg_base + 0xa24 + i*4);
    md[i*4] = (val & 0xff000000) >> 24;
    md[i*4+1] = (val & 0x00ff0000) >> 16;
    md[i*4+2] = (val & 0x0000ff00) >> 8;
    md[i*4+3] = (val & 0x000000ff);
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
  c->md_len = SHA256_DIGEST_LENGTH;

  *(unsigned int *)(reg_base + 0x920) = 0x10;
  return 1;
}

static void sha256_transform(const void *buffer, int last, size_t last_len)
{
  int i = 0;
  const unsigned int *p = buffer;
  for (i = 0; i < 16; i++) {
    *(unsigned int *)(reg_base + 0x9e4 + i*4) = p[i];
  }

  if (last == 0) {
    *(unsigned int *)(reg_base + 0x988) = 0x80000;
    *(unsigned int *)(reg_base + 0x984) = 0xf0000005;
  } else {
    *(unsigned int *)(reg_base + 0x988) = 0x80000;
    *(unsigned int *)(reg_base + 0x984) = 0xf0004005 | (last_len << 4);
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
  unsigned int *md_p = (unsigned int *)md;
  int m = c->Nl;
  int len = c->Nh;
  int i = 0;

  if (m < 56) { // the last block
    tmp[m] = 0x80;
    tmp[60] = ((len << 3) & 0xff000000) >> 24;
    tmp[61] = ((len << 3) & 0x00ff0000) >> 16;
    tmp[62] = ((len << 3) & 0x0000ff00) >> 8;
    tmp[63] = ((len << 3) & 0x000000ff);
    sha256_transform(tmp, 1, m << 3);
  } else {
    tmp[m] = 0x80;
    sha256_transform(tmp, 0, 0); // the second last
    memset(tmp, 0, sizeof(tmp));
    tmp[60] = ((len << 3) & 0xff000000) >> 24;
    tmp[61] = ((len << 3) & 0x00ff0000) >> 16;
    tmp[62] = ((len << 3) & 0x0000ff00) >> 8;
    tmp[63] = ((len << 3) & 0x000000ff);
    sha256_transform(tmp, 1, m << 3);
  }

  for (i = 0; i < 8; i++) {
    // This is big endian, not need switch
    md_p[i] = *(unsigned int *)(reg_base + 0xa24 + i*4);
  }

  return 1;
}
