/*
 * hw_rsa.c
 * Originally written by Zhao Junwang<zhjwpku@gmail.com> for the cryptop 
 * safemodule.
 */

#include <openssl/evp.h>
#include <string.h>
#include <openssl/rsa.h>

#include "common.h"

#if IS_CRYPTOP

#define HW_RSA_NAME "cryptop RSA"

static int rsa_pub_encypt(int flen, const unsigned char *from,
		       unsigned char *to, RSA *rsa, int padding);
static int rsa_pub_decrypt(int flen, const unsigned char *from,
		       unsigned char *to, RSA *rsa, int padding);
static int rsa_priv_encrypt(int flen, const unsigned char *from,
			unsigned char *to, RSA *rsa, int padding);
static int rsa_priv_decrypt(int flen, const unsigned char *from,
			unsigned char *to, RSA *rsa, int padding);
static int rsa_mod_exp(BIGNUM *r0, const BIGNUM *I, RSA *rsa, BN_CTX *ctx);
static int bn_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
		      const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);
static int rsa_init(RSA *rsa);
static int rsa_finish(RSA *rsa);

// The engine calls this function to initial RSA
void engine_rsa_init(RSA_METHOD *rsa)
{
  memcpy(rsa, RSA_PKCS1_SSLeay(), sizeof(RSA_METHOD));
  rsa->name = HW_RSA_NAME;
  return;
}

// The implementations
static int rsa_pub_encypt(int flen, const unsigned char *from,
		       unsigned char *to, RSA *rsa, int padding)
{
  return 1;
}

static int rsa_pub_decrypt(int flen, const unsigned char *from,
		       unsigned char *to, RSA *rsa, int padding)
{
  return 1;
}

static int rsa_priv_encrypt(int flen, const unsigned char *from,
			unsigned char *to, RSA *rsa, int padding)
{
  return 1;
}

static int rsa_priv_decrypt(int flen, const unsigned char *from,
			unsigned char *to, RSA *rsa, int padding)
{
  return 1;
}

static int rsa_mod_exp(BIGNUM *r0, const BIGNUM *I, RSA *rsa, BN_CTX *ctx)
{
  return 1;
}

static int bn_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
		      const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)
{
  return 1;
}

static int rsa_init(RSA *rsa)
{
  return 1;
}

static int rsa_finish(RSA *rsa)
{
  return 1;
}
#endif
