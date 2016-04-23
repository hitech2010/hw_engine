/* This define in this file could be included by some files */
#ifndef HEADER_COMMON_H
#define HEADER_COMMON_H

#include <openssl/aes.h>
#include <openssl/modes.h>
#include <openssl/err.h>
#include <openssl/sms4.h>

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
#define REG_AES		__REG(reg_base + 0x29a*4)
#define REG_SM4		__REG(reg_base + 0x29a*4)

#define REG_MSG(id)	__REG(reg_base + 0x279*4 + id * 4)
#define REG_HASH(id)	__REG(reg_base + 0x289*4 + id * 4)
#define REG_KEY(id)	__REG(reg_base + 0x2a0*4 + id * 4)
#define REG_IV(id)	__REG(reg_base + 0x2ac*4 + id * 4)
#define REG_TEXT(id)	__REG(reg_base + 0x2a8*4 + id * 4)
#define REG_RESULT(id)	__REG(reg_base + 0x29c*4 + id * 4)

/* The Instructions */
#define HASH_PORT_HIG	(0x1 << 19)
#define HASH_PORT_LOW(last_block,block_len,alg,lock_c)	((((last_block)&0x1)<<14) \
	      | (((block_len)&0x3ff)<<4) | (((alg)&0x3)<<2) | (((lock_c)&0x1)<<1) | (0xf<<28))
#define BC_INI(alg, key_len, enc, mode, fbsel) ((((alg)&0x3) << 26) | (((key_len)&0x3) << 24) \
	      | (((enc)&0x1) << 23) | (((mode)&0x7) << 15) | (((fbsel)&0x3) << 13) \
	      | (0x1 << 18))
#define KEXP(alg, key_len, enc, mode, fbsel) ((((alg)&0x3) << 26) | (((key_len)&0x3) << 24) \
	      | (((enc)&0x1) << 23) | (((mode)&0x7) << 15) | (((fbsel)&0x3) << 13) \
	      | (0x1 << 22) | (0x1 << 18))

#define ED(alg, key_len, enc, mode, fbsel, lock_c) ((((alg)&0x3) << 26) | (((key_len)&0x3) << 24) \
	      | (((enc)&0x1) << 23) | (((mode)&0x7) << 15) | (((fbsel)&0x3) << 13) \
	      | (((lock_c)&0x1) << 12) | (0x1 << 21) | (0x1 << 18))

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
  aes_cipher,			  \
  NULL,				  \
  0,				  \
  EVP_CIPHER_set_asn1_iv,	  \
  EVP_CIPHER_get_asn1_iv,	  \
  NULL,				  \
  NULL				  \
}

#define DECLARE_SM4_EVP(ksize, lmode, umode)	\
static const EVP_CIPHER sm4_##ksize##_##lmode = {	\
  NID_sms4##_##lmode,	  	  \
  EVP_CIPHER_block_size_##umode,  \
  16,				  \
  16,				  \
  0 | EVP_CIPH_##umode##_MODE,	  \
  sm4_init_key,			  \
  sm4_do_cipher,		  \
  NULL,				  \
  0,				  \
  EVP_CIPHER_set_asn1_iv,	  \
  EVP_CIPHER_get_asn1_iv,	  \
  NULL,				  \
  NULL				  \
}

#define NID_sms4_cfb NID_sms4_cfb128
#define NID_sms4_ofb NID_sms4_ofb128

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

#define SM4_ECB	1
#define SM4_CBC 2
#define SM4_OFB 3
#define SM4_CFB 4

#define	EVP_CIPHER_block_size_ECB	AES_BLOCK_SIZE
#define	EVP_CIPHER_block_size_CBC	AES_BLOCK_SIZE
#define	EVP_CIPHER_block_size_OFB	1
#define	EVP_CIPHER_block_size_CFB	1
#define	EVP_CIPHER_block_size_CTR	1

#define GETU32(pc) (\
	    ((unsigned int)(pc)[0] << 24) ^ \
	    ((unsigned int)(pc)[1] << 16) ^ \
	    ((unsigned int)(pc)[2] <<  8) ^ \
	    ((unsigned int)(pc)[3]))

#define PUTU32(st, ct) { \
	    (ct)[0] = (unsigned char)((st) >> 24); \
	    (ct)[1] = (unsigned char)((st) >> 16); \
	    (ct)[2] = (unsigned char)((st) >>  8); \
	    (ct)[3] = (unsigned char)(st); }

typedef struct SM1_Cipher_Data {
  AES_KEY ks;
} SM1_Cipher_Data;

#define MY_DATA_LEN	(1024*9)	//9K

struct MY_DATA {
  int con[8];
  char msg[MY_DATA_LEN - 32];		//at most 8192 char
};

#endif
