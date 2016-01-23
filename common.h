/* This define in this file could be included by some files */
#ifndef HEADER_COMMON_H
#define HEADER_COMMON_H

#define CRYPTOP_BASE 0xC0900000
#define CRYPTOP_SIZE 0x80000	//512KB
#define CRYPTOP_INTR 0xee600004

/* Use this when declaring EVP_CIPHER structs */
#define DECLARE_AES_EVP(ksize, lmode, umode)	\
static const EVP_CIPHER aes_##ksize##_##lmode = {	\
  NID_aes_##ksize##_##lmode,	  \
  EVP_CIPHER_block_size_##umode,  \
  AES_KEY_SIZE_##ksize,		  \
  AES_BLOCK_SIZE,		  \
  0 | EVP_CIPH_##umode##_MODE,	  \
  NULL,				  \
  NULL,				  \
  NULL,				  \
  0,				  \
  EVP_CIPHER_set_asn1_iv,	  \
  EVP_CIPHER_get_asn1_iv,	  \
  NULL,				  \
  NULL				  \
}

#define HW_AES_128_ECB	1
#define HW_AES_128_CBC	2
#define HW_AES_128_CFB	3
#define HW_AES_128_OFB	4

#endif
