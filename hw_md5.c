#include <openssl/evp.h>
#include <openssl/md5.h>

/* Begin: MD5 implementations */
int md5_init(EVP_MD_CTX *ctx)
{
  return 1;
}

int md5_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
  return 1;
}

int md5_final(EVP_MD_CTX *ctx, unsigned char *md)
{
  return 1;
}
/* End: MD5 implementations */

