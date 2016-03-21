/*
 * hw_sm234.c
 * Originally written by Zhao Junwang<zhjwpku@gmail.com> for the cryptop 
 * safemodule.
 */

#include <string.h>
#include <openssl/evp.h>
#include <openssl/sms4.h>
#include <openssl/objects.h>

#include "common.h"

#if IS_CRYPTOP
// SM3
static int sm3_init(EVP_MD_CTX *ctx);
static int sm3_update(EVP_MD_CTX *ctx, const void *data, size_t len);
static int sm3_final(EVP_MD_CTX *ctx, unsigned char *md);

void engine_sm3_init(EVP_MD *digest_sm3)
{
  memcpy(digest_sm3, EVP_sm3, sizeof(EVP_MD));
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
/*  case SM4_OFB:
    memcpy(sm4_cipher, EVP_sms4_ofb128(), sizeof(EVP_CIPHER));
    break;
*/
  case SM4_CFB:
    memcpy(sm4_cipher, EVP_sms4_cfb128(), sizeof(EVP_CIPHER));
    break;
  }
}

// SM3 implementatins
static int sm3_init(EVP_MD_CTX *ctx)
{
  return 1;
}

static int sm3_update(EVP_MD_CTX *ctx, const void *data, size_t len)
{
  return 1;
}

static int my_sm3_final(EVP_MD_CTX *ctx, unsigned char *md)
{
  return 1;
}

#endif
