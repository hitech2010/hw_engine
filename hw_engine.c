/*
 * hw_engine.c
 * Originally written by Zhao Junwang<zhjwpku@gmail.com> for the cryptop 
 * safemodule.
 * This project implements a engine accelerate the following algorithms:
 * 	SHA1/SHA256
 * 	AES128/AES192/AES256
 * 	RSA/ECC
 */

#include <stdio.h>
#include <string.h>

#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "common.h"

#define HW_ENGINE_ID	"hw_engine"
#define	HW_ENGINE_NAME	"An OpenSSL engine for cryptop"

unsigned int reg_base = 0;
unsigned int fd = -1;

/*-------------------------The Engine Digests-------------------------*/

/* md5 */
extern void engine_md5_init(EVP_MD *);
static EVP_MD digest_md5;

/* sha1 */
extern void engine_sha1_init(EVP_MD *);
static EVP_MD digest_sha1;

/* sha256 */
extern void engine_sha256_init(EVP_MD *);
static EVP_MD digest_sha256;

/* digests */
static int digest_nids[] = { NID_md5, NID_sha1, NID_sha256, 0 };
static int digests(ENGINE *e, const EVP_MD **digest,
                   const int **nids, int nid)
{
  int ok = 1;
  if (!digest) {
    /* We are returning a list of supported nids */
    *nids = digest_nids;
    return (sizeof(digest_nids) - 1) / sizeof(digest_nids[0]);
  }

  /* We are being asked for a specific digest */
  switch (nid) {
  case NID_md5:
    *digest = &digest_md5;
    break;
  case NID_sha1:
    *digest = &digest_sha1;
    break;
  case NID_sha256:
    *digest = &digest_sha256;
    break;
  default:
    ok = 0;
    *digest = NULL;
    break;
  }
  return ok;
}

/*-------------------------The Engine Ciphers-------------------------*/

/* AES */
static EVP_CIPHER aes_128_ecb;
static EVP_CIPHER aes_128_cbc;
static EVP_CIPHER aes_128_ofb;
static EVP_CIPHER aes_128_cfb;
extern void engine_cipher_init(EVP_CIPHER *cipher, int type);

static int cipher_nids[] = {  // 
// AES 128 bits, ecb, cbc, ofb, cfb, ctr
  NID_aes_128_ecb,
  NID_aes_128_cbc,
  NID_aes_128_ofb128,
  NID_aes_128_cfb128,
#if 0	// TODO: add the followings
  NID_aes_128_ctr,
// AES 192 bits, ecb, cbc, ofb, cfb
  NID_aes_192_ecb,
  NID_aes_192_cbc,
  NID_aes_192_ofb128,
  NID_aes_192_cfb128,
  NID_aes_192_ctr,
// AES 192 bits, ecb, cbc, ofb, cfb
  NID_aes_256_ecb,
  NID_aes_256_cbc,
  NID_aes_256_ofb128,
  NID_aes_256_cfb128,
  NID_aes_256_ctr,
#endif
  0
};

static int ciphers(ENGINE *e, const EVP_CIPHER **cipher,
		   const int **nids, int nid)
{
  if (!cipher) {
    *nids = cipher_nids;
    return (sizeof(cipher_nids) - 1) / sizeof(digest_nids[0]);
  }

  switch (nid) {
  case NID_aes_128_ecb:
    *cipher = &aes_128_ecb;
    break;
  case NID_aes_128_cbc:
    *cipher = &aes_128_cbc;
    break;
  case NID_aes_128_ofb128:
    *cipher = &aes_128_ofb;
    break;
  case NID_aes_128_cfb128:
    *cipher = &aes_128_cbc;
    break;
  default:
    *cipher = NULL;
    return 0;
  }

  return 1;
}

/*-------------------------The Engine RSA-------------------------*/

static RSA_METHOD hw_rsa;
extern void engine_rsa_init(RSA_METHOD *);


/*-------------------------The Engine RAND-------------------------*/
static RAND_METHOD hw_rand;
extern void engine_rand_init(RAND_METHOD *);

/*---------------------The Engine INIT & BIND----------------------*/
/* 
 * This is the function used by ENGINE_set_init_function.
 * We now use the OPENSSL builtin implementations. Should be
 * replaced by the cryptop functions.
*/
static int cryptop_init(ENGINE *e)
{
  int i;

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

  /* digests */
  engine_md5_init(&digest_md5);
  engine_sha1_init(&digest_sha1);
  engine_sha256_init(&digest_sha256);

  /* ciphers */
  engine_cipher_init(&aes_128_ecb, HW_AES_128_ECB);
  engine_cipher_init(&aes_128_cbc, HW_AES_128_CBC);
  engine_cipher_init(&aes_128_ofb, HW_AES_128_CFB);
  engine_cipher_init(&aes_128_cfb, HW_AES_128_OFB);

  /* rsa */
  engine_rsa_init(&hw_rsa);

  /* rand */
  engine_rand_init(&hw_rand);

  return 1;
};

/* This function will be called when the
 * Engine got finished.
 */
static int cryptop_finish(ENGINE *e)
{
  if (reg_base)
    munmap((void *)reg_base, CRYPTOP_SIZE);

  if (fd > 0)
    close(fd);

  return 1;
}

static int cryptop_bind_helper(ENGINE *e)
{
  if (!ENGINE_set_id(e, HW_ENGINE_ID) ||
      !ENGINE_set_name(e, HW_ENGINE_NAME) ||
      !ENGINE_set_init_function(e, cryptop_init) ||
      !ENGINE_set_digests(e, digests) ||
      !ENGINE_set_ciphers(e, ciphers) ||
      !ENGINE_set_RSA(e, &hw_rsa) ||
      !ENGINE_set_RAND(e, &hw_rand) ||
      !ENGINE_set_finish_function(e, cryptop_finish)) {
    return 0;
  }

  return 1;
}

static int cryptop_bind_fn(ENGINE *e, const char *id)
{
  if (id && strcmp(id, HW_ENGINE_ID)) {
    fprintf(stderr, "Bad engine id %s, expected id is %s\n", id, HW_ENGINE_ID);
    return 0;
  }
  if (!cryptop_bind_helper(e)) {
    fprintf(stderr, "Bind failed\n");
  }

  return 1;
}

IMPLEMENT_DYNAMIC_BIND_FN(cryptop_bind_fn)
IMPLEMENT_DYNAMIC_CHECK_FN()
