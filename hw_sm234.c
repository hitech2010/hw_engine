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
// SM3
static int sm3_init(EVP_MD_CTX *ctx);
static int sm3_update(EVP_MD_CTX, const void *data, size_t len);
static int sm3_final(EVP_MD_CTX, unsigned char *md);

void engine_sm3_init(EVP_MD *digest_sm3)
{
  memcpy(digest_sm3, EVP_sm3, sizeof(EVP_MD));
}

// SM4
int sm4_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc);

// SM3 implementatins
static int sm3_init(EVP_MD_CTX *ctx)
{
  return 1;
}

static int sm3_update(EVP_MD_CTX, const void *data, size_t len)
{
  return 1;
}

static int sm3_final(EVP_MD_CTX, unsigned char *md)
{
  return 1;
}

#endif
