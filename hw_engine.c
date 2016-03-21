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
#include <stdlib.h>

#include <openssl/opensslconf.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/modes.h>
#include <openssl/obj_mac.h>
#include <unistd.h>
//#include <fcntl.h>
#include <asm-generic/fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "common.h"

#define HW_ENGINE_ID	"hw_engine"
#define	HW_ENGINE_NAME	"An OpenSSL engine for cryptop and USBKey"

#define FILE_PATH "/mnt/sysfile.a"

unsigned int fd = -1;
unsigned int reg_base = 0;

struct MY_DATA *tmp_in = NULL;

#if IS_CRYPTOP

/*-------------------------The Engine Digests-------------------------*/

/* sha1 */
extern void engine_sha1_init(EVP_MD *);
static EVP_MD digest_sha1;

/* sha256 */
extern void engine_sha256_init(EVP_MD *);
static EVP_MD digest_sha256;

/* sm3 */
extern void engine_sm3_init(EVP_MD *);
static EVP_MD digest_sm3;

/* digests */
static int digest_nids[] = { NID_sha1, NID_sha256, NID_sm3, 0 };
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
  case NID_sha1:
    *digest = &digest_sha1;
    break;
  case NID_sha256:
    *digest = &digest_sha256;
    break;
  case NID_sm3:
    *digest = &digest_sm3;
    break;
  default:
    ok = 0;
    *digest = NULL;
    break;
  }
  return ok;
}
#endif

/*-------------------------The Engine Ciphers-------------------------*/
#if IS_CRYPTOP
/* These are the function prototypes, implemented in hw_aes.c */
extern int aes_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
			const unsigned char *iv, int enc);
extern int aes_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
			  const unsigned char *in, size_t len);
extern int aes_ecb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
			  const unsigned char *in, size_t len);
extern int aes_cfb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
			  const unsigned char *in, size_t len);
extern int aes_ofb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
			  const unsigned char *in, size_t len);
extern int aes_ctr_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
			  const unsigned char *in, size_t len);

/* AES, use macro here to make the code clean */
DECLARE_AES_EVP(128,ecb,ECB);
DECLARE_AES_EVP(128,cbc,CBC);
DECLARE_AES_EVP(128,ofb,OFB);
DECLARE_AES_EVP(128,cfb,CFB);
DECLARE_AES_EVP(128,ctr,CTR);

DECLARE_AES_EVP(192,ecb,ECB);
DECLARE_AES_EVP(192,cbc,CBC);
DECLARE_AES_EVP(192,ofb,OFB);
DECLARE_AES_EVP(192,cfb,CFB);
DECLARE_AES_EVP(192,ctr,CTR);

DECLARE_AES_EVP(256,ecb,ECB);
DECLARE_AES_EVP(256,cbc,CBC);
DECLARE_AES_EVP(256,ofb,OFB);
DECLARE_AES_EVP(256,cfb,CFB);
DECLARE_AES_EVP(256,ctr,CTR);
#endif

#if IS_USBKEY
extern int sm1_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
			const unsigned char *iv, int enc);
extern int sm1_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
			 const unsigned char *in, size_t len);

static const EVP_CIPHER sm1_128 = {
  //NID_SM1_128,
  NID_aes_128_cbc,
  16,			//block size
  16,			//key size 128 bit
  16,			//iv len
  0,			//various flags
  sm1_init_key,		//init key
  sm1_do_cipher,	//encrypt/decrypt data
  NULL,			//cleanup ctx
  sizeof(SM1_Cipher_Data) + 16,	// how big ctx->data needs to be
  EVP_CIPHER_set_asn1_iv,
  EVP_CIPHER_get_asn1_iv,
  NULL,
  NULL
};
#endif

/* List of supported ciphers. */
static int cipher_nids[] = {
#if IS_CRYPTOP 
// AES 128 bits, ecb, cbc, ofb, cfb, ctr
  NID_aes_128_ecb,
  NID_aes_128_cbc,
  NID_aes_128_ofb128,
  NID_aes_128_cfb128,
  NID_aes_128_ctr,

// AES 192 bits, ecb, cbc, ofb, cfb
  NID_aes_192_ecb,
  NID_aes_192_cbc,
  NID_aes_192_ofb128,
  NID_aes_192_cfb128,
  NID_aes_192_ctr,

// AES 256 bits, ecb, cbc, ofb, cfb
  NID_aes_256_ecb,
  NID_aes_256_cbc,
  NID_aes_256_ofb128,
  NID_aes_256_cfb128,
  NID_aes_256_ctr,

// SM4 ecb, cbc, ofb, cfb
  NID_sms4_ecb,
  NID_sms4_cbc,
  NID_sms4_ofb128,
  NID_sms4_cfb128,
#endif

#if IS_USBKEY
  //NID_SM1_128,	// use NID_aes_128_cbc
  NID_aes_128_cbc,
#endif
  0
};

static int ciphers(ENGINE *e, const EVP_CIPHER **cipher,
		   const int **nids, int nid)
{
  if (!cipher) {
    *nids = cipher_nids;
    return (sizeof(cipher_nids) - 1) / sizeof(cipher_nids[0]);
  }

  switch (nid) {
#if IS_CRYPTOP
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
    *cipher = &aes_128_cfb;
    break;
  case NID_aes_128_ctr:
    *cipher = &aes_128_ctr;
    break;

  case NID_aes_192_ecb:
    *cipher = &aes_192_ecb;
    break;
  case NID_aes_192_cbc:
    *cipher = &aes_192_cbc;
    break;
  case NID_aes_192_ofb128:
    *cipher = &aes_192_ofb;
    break;
  case NID_aes_192_cfb128:
    *cipher = &aes_192_cfb;
    break;
  case NID_aes_192_ctr:
    *cipher = &aes_192_ctr;
    break;

  case NID_aes_256_ecb:
    *cipher = &aes_256_ecb;
    break;
  case NID_aes_256_cbc:
    *cipher = &aes_256_cbc;
    break;
  case NID_aes_256_ofb128:
    *cipher = &aes_256_ofb;
    break;
  case NID_aes_256_cfb128:
    *cipher = &aes_256_cfb;
    break;
  case NID_aes_256_ctr:
    *cipher = &aes_256_ctr;
    break;
#endif

#if IS_USBKEY
  //case NID_SM1_128:
  //  *cipher = &sm1_128;
  //  break;
  case NID_aes_128_cbc:
    *cipher = &sm1_128;
    break;

#endif
  default:
    *cipher = NULL;
    return 0;
  }

  return 1;
}

#if IS_CRYPTOP
/*-------------------------The Engine RSA-------------------------*/

static RSA_METHOD hw_rsa;
extern void engine_rsa_init(RSA_METHOD *);


/*-------------------------The Engine RAND-------------------------*/
static RAND_METHOD hw_rand;
extern void engine_rand_init(RAND_METHOD *);
#endif

#if IS_USBKEY

#endif

/*---------------------The Engine INIT & BIND----------------------*/
/* 
 * This is the function used by ENGINE_set_init_function.
 * We now use the OPENSSL builtin implementations. Should be
 * replaced by the cryptop functions.
*/

static int cryptop_init(ENGINE *e)
{
  int ret;
#if IS_CRYPTOP
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
  engine_sha1_init(&digest_sha1);
  engine_sha256_init(&digest_sha256);

  /* ciphers */
  // The ciphers are initialized with the DECLARE_AES_EVP macro

  /* rsa */
  engine_rsa_init(&hw_rsa);

  /* rand */
  engine_rand_init(&hw_rand);
#endif

#if IS_USBKEY
  fd = open(FILE_PATH, O_RDWR | O_DIRECT);
  if (fd < 0) {
    fprintf(stderr, "Can't open %s\n", FILE_PATH);
    return 0;
  }
  /* cannot use malloc here, don't know why*/
  ret = posix_memalign((void **)&tmp_in, 1024, sizeof(struct MY_DATA));

  if (tmp_in == NULL)
    printf("%s malloc return NULL\n", __func__);

#endif

  return 1;
};

/* This function will be called when the
 * Engine got finished.
 */
static int cryptop_finish(ENGINE *e)
{
#if IS_CRYPTOP
  if (reg_base)
    munmap((void *)reg_base, CRYPTOP_SIZE);

#endif

  if (fd > 0)
    close(fd);

#if IS_USBKEY
  free(tmp_in);
  tmp_in = NULL;
#endif

  return 1;
}

static int cryptop_bind_helper(ENGINE *e)
{
  if (!ENGINE_set_id(e, HW_ENGINE_ID) ||
      !ENGINE_set_name(e, HW_ENGINE_NAME) ||
      !ENGINE_set_init_function(e, cryptop_init) ||
      !ENGINE_set_ciphers(e, ciphers) ||
#if IS_CRYPTOP
      !ENGINE_set_digests(e, digests) ||
      !ENGINE_set_RSA(e, &hw_rsa) ||
      !ENGINE_set_RAND(e, &hw_rand) ||
#endif
      !ENGINE_set_finish_function(e, cryptop_finish)) {
    return 0;
  }

  return 1;
}

static ENGINE * ENGINE_hw(void)
{
  ENGINE *eng = ENGINE_new();
  if (!eng) {
    return NULL;
  }

  if (!cryptop_bind_helper(eng)) {
    ENGINE_free(eng);
    return NULL;
  }

  return eng;
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
