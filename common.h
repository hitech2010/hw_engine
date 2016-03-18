/* This define in this file could be included by some files */
#ifndef HEADER_COMMON_H
#define HEADER_COMMON_H

#include <openssl/aes.h>
#include <openssl/modes.h>
#include <openssl/err.h>

#define IS_CRYPTOP	1
#define IS_USBKEY	0

#define CRYPTOP_BASE 0xC0900000
#define CRYPTOP_SIZE 0x80000	//512KB
#define CRYPTOP_INTR 0xee600004

/* The Registers */
#define __REG(x)	(*(unsigned int *)(x))
#define REG_MODE	__REG(reg_base + 0x248*4)
#define REG_HASH_PORT_HIG	__REG(reg_base + 0x262*4)
#define REG_HASH_PORT_LOW	__REG(reg_base + 0x261*4)

/* The Instructions */
#define HASH_PORT_HIG	(0x1 << 19)
#define HASH_PORT_LOW(last_block,block_len,alg,lock_c)	((((last_block)&0x1)<<14) \
	      | (((block_len)&0x3ff)<<4) | (((alg)&0x3)<<2) | (((lock_c)&0x1)<<1) | (0xf<<28))

/* Use this when declaring EVP_CIPHER structs, declaring so many ciphers
 * by hand would be pain.
 */
#define DECLARE_AES_EVP(ksize, lmode, umode)	\
static const EVP_CIPHER aes_##ksize##_##lmode = {	\
  NID_aes_##ksize##_##lmode,	  \
  EVP_CIPHER_block_size_##umode,  \
  AES_KEY_SIZE_##ksize,		  \
  AES_BLOCK_SIZE,		  \
  0 | EVP_CIPH_##umode##_MODE,	  \
  aes_init_key,			  \
  aes_##lmode##_cipher,		  \
  NULL,				  \
  sizeof(HW_Cipher_Data),	  \
  EVP_CIPHER_set_asn1_iv,	  \
  EVP_CIPHER_get_asn1_iv,	  \
  NULL,				  \
  NULL				  \
}

#define NID_aes_128_cfb NID_aes_128_cfb128
#define NID_aes_128_ofb NID_aes_128_ofb128

#define NID_aes_192_cfb NID_aes_192_cfb128
#define NID_aes_192_ofb NID_aes_192_ofb128

#define NID_aes_256_cfb NID_aes_256_cfb128
#define NID_aes_256_ofb NID_aes_256_ofb128

#define AES_ENCRYPT		1
#define AES_DECRYPT		0
#define AES_BLOCK_SIZE		16
#define AES_KEY_SIZE_128	16
#define AES_KEY_SIZE_192	24
#define AES_KEY_SIZE_256	32

#define	EVP_CIPHER_block_size_ECB	AES_BLOCK_SIZE
#define	EVP_CIPHER_block_size_CBC	AES_BLOCK_SIZE
#define	EVP_CIPHER_block_size_OFB	1
#define	EVP_CIPHER_block_size_CFB	1
#define	EVP_CIPHER_block_size_CTR	1

typedef struct hw_cipher_data {
  union {
    double align;
    AES_KEY ks;
  } ks;
  block128_f block;
  union {
    cbc128_f cbc;
    ctr128_f ctr;
  } stream;
} HW_Cipher_Data;

typedef struct SM1_Cipher_Data {
  AES_KEY ks;
} SM1_Cipher_Data;

#define MY_DATA_LEN	(1024*9)	//9K

struct MY_DATA {
  int con[8];
  char msg[MY_DATA_LEN - 32];		//at most 8192 char
};

#endif
