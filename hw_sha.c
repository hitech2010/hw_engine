/*
 * hw_sha.c
 * Originally written by Zhao Junwang<zhjwpku@gmail.com> for the cryptop 
 * safemodule.
 * This project implements a engine accelerate the following algorithms:
 */

#include <openssl/evp.h>
#include <string.h>
#include <openssl/sha.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include "common.h"

extern unsigned int reg_base;
extern unsigned int fd;

// SHA1, namely SHA160
static int sha1_init(EVP_MD_CTX *ctx);
static int sha1_update(EVP_MD_CTX *ctx, const void *data, size_t count);
static int sha1_final(EVP_MD_CTX *ctx, unsigned char *md);

static int sha256_init(EVP_MD_CTX *ctx);
static int sha256_update(EVP_MD_CTX *ctx, const void *data, size_t count);
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
}

// The sha1 implementatitons
static int sha1_init(EVP_MD_CTX *ctx)
{
  fd = open("/dev/mem", O_RDWR | O_SYNC);
  if (fd < 0) {
    fprintf(stderr, "Can't open /dev/mem\n");
    return 0;
  }

  reg_base = (unsigned int) mmap(NULL, CRYPTOP_SIZE, PROT_READ | PROT_WRITE |
				 MAP_FIXED, MAP_SHARED, fd, CRYPTOP_BASE);
  if (reg_base == (unsigned int) MAP_FAILED) {
    reg_base = 0;
    fprintf(stderr, "mmap cryptop error\n");
    close(fd);
    fd = -1;
    return 0;
  }

  return 1;
}

/* Hash a single 512-bit block. This is the core of the algorithm */
static void sha1_transform(SHA_CTX *c, const SHA_LONG buffer[64])
{
  
}

static int sha1_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
  SHA_CTX *c = (SHA_CTX *)(ctx->md_data);
  int i = 0;
  const unsigned int p[16] = {0x31800000, 0x0, 0x0, 0x0,
			      0x0, 0x0, 0x0, 0x0,
			      0x0, 0x0, 0x0, 0x0,
			      0x0, 0x0, 0x0, 0x8};
  
  *(unsigned int *)(reg_base + 0x920) = 0x10;
  
  for(i = 0; i < 16; i++) {
    *(unsigned int *)(reg_base + 0x9e4 + i*4) = p[i];
  }
  
  *(unsigned int *)(reg_base + 0x988) = 0x80000;
  *(unsigned int *)(reg_base + 0x984) = 0xf0004089;
  
  //usleep(10);

  c->h0 = *(unsigned int *)(reg_base + 0xa24);
  c->h1 = *(unsigned int *)(reg_base + 0xa28);
  c->h2 = *(unsigned int *)(reg_base + 0xa2c);
  c->h3 = *(unsigned int *)(reg_base + 0xa30);
  c->h4 = *(unsigned int *)(reg_base + 0xa34);

  printf("%x\n%x\n%x\n%x\n%x\n", c->h0, c->h1, c->h2, c->h3, c->h4);
  return 1;
}

static int sha1_final(EVP_MD_CTX *ctx, unsigned char *md)
{
  SHA_CTX *c = (SHA_CTX *)(ctx->md_data);
  
  printf("%x\n%x\n%x\n%x\n%x\n", c->h0, c->h1, c->h2, c->h3, c->h4);
  md[0] = (c->h0 & 0xff000000) >> 24;
  md[1] = (c->h0 & 0x00ff0000) >> 16;
  md[2] = (c->h0 & 0x0000ff00) >> 8;
  md[3] = c->h0 & 0x000000ff;

  md[4] = (c->h1 & 0xff000000) >> 24;
  md[5] = (c->h1 & 0x00ff0000) >> 16;
  md[6] = (c->h1 & 0x0000ff00) >> 8;
  md[7] = c->h1 & 0x000000ff;

  md[8] = (c->h2 & 0xff000000) >> 24;
  md[9] = (c->h2 & 0x00ff0000) >> 16;
  md[10] = (c->h2 & 0x0000ff00) >> 8;
  md[11] = c->h2 & 0x000000ff;

  md[12] = (c->h3 & 0xff000000) >> 24;
  md[13] = (c->h3 & 0x00ff0000) >> 16;
  md[14] = (c->h3 & 0x0000ff00) >> 8;
  md[15] = c->h3 & 0x000000ff;

  md[16] = (c->h4 & 0xff000000) >> 24;
  md[17] = (c->h4 & 0x00ff0000) >> 16;
  md[18] = (c->h4 & 0x0000ff00) >> 8;
  md[19] = c->h4 & 0x000000ff;

  if (reg_base)
    munmap((void *)reg_base, CRYPTOP_SIZE);

  if (fd > 0)
    close(fd);

  return 1;
}

// The sha256 implementatitons
static int sha256_init(EVP_MD_CTX *ctx)
{
  return 1;
}

static int sha256_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
  return 1;
}

static int sha256_final(EVP_MD_CTX *ctx, unsigned char *md)
{
  return 1;
}
