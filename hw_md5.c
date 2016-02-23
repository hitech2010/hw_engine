#include <openssl/evp.h>
#include <string.h>
#include <openssl/md5.h>

static int md5_init(EVP_MD_CTX *ctx);
static int md5_update(EVP_MD_CTX *ctx, const void *data, size_t count);
static int md5_final(EVP_MD_CTX *ctx, unsigned char *md);

// The engine calls this function to initial EVP_md5
void engine_md5_init(EVP_MD * digest_md5)
{
/* 
 * For now It takes a copy of the builtin OpenSSL MD5WithRSAEncryption
 * implementation and just changes the init/update/final function
 * pointers, thereby keeping the PKEY implementation from OpenSSL.
 */
  memcpy(digest_md5, EVP_md5(), sizeof(EVP_MD));
/*
  digest_md5->init = md5_init;
  digest_md5->update = md5_update;
  digest_md5->final = md5_final;
  digest_md5->block_size = 64;
  digest_md5->ctx_size = sizeof(MD5_CTX);
*/
}

// The implementatitons
static int md5_init(EVP_MD_CTX *ctx)
{
  return 1;
}

static int md5_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
  return 1;
}

static int md5_final(EVP_MD_CTX *ctx, unsigned char *md)
{
  return 1;
}
