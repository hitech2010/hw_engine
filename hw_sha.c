/*
 * hw_sha.c
 * Originally written by Zhao Junwang<zhjwpku@gmail.com> for the cryptop 
 * safemodule.
 * This project implements a engine accelerate the following algorithms:
 */

#include <openssl/evp.h>
#include <string.h>
#include <openssl/sha.h>
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
  //digest_sha1->init = sha1_init;
  digest_sha1->update = sha1_update;
  //digest_sha1->final = sha1_final;
}

// The engine calls this function to initial EVP_MD sha256
void engine_sha256_init(EVP_MD * digest_sha256)
{
  memcpy(digest_sha256, EVP_sha256(), sizeof(EVP_MD));
}

// The sha1 implementatitons
static int sha1_init(EVP_MD_CTX *ctx)
{
  return SHA1_Init(ctx->md_data);
}

/* This is the real hash function */
static int sha1_update_helper(SHA_CTX *c, const void *data, size_t len)
{

}

static int sha1_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
  return SHA1_Update(ctx->md_data, data, count);
}

static int sha1_final(EVP_MD_CTX *ctx, unsigned char *md)
{
  return SHA1_Final(md, ctx->md_data);
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
