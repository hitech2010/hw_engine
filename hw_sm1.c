/*
 * hw_aes.c
 * Originally written by Zhao Junwang<zhjwpku@gmail.com> for the cryptop 
 * safemodule.
 */

#include <string.h>

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/modes.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>

#include "common.h"

#if IS_USBKEY

extern unsigned int fd;
extern struct MY_DATA *tmp_in;

int sm1_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
		 const unsigned char *iv, int enc)
{
  int ret;
  SM1_Cipher_Data *dat = (SM1_Cipher_Data *)(ctx->cipher_data);
  
  if (!enc){	//decryption
    ret = AES_set_decrypt_key(key, EVP_CIPHER_CTX_key_length(ctx) * 8, 
			      &dat->ks);
  } else {	//encryption
    ret = AES_set_encrypt_key(key, EVP_CIPHER_CTX_key_length(ctx) * 8,
			      &dat->ks);
  }

  if (ret < 0) {
    /* TODO We need to add our own err handle */
    EVPerr(EVP_F_AES_INIT_KEY, EVP_R_AES_KEY_SETUP_FAILED);
    return 0;
  }

  return 1;
}

int sm1_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
		  const unsigned char *in, size_t len) {
  /* Each time we do 4096 char, and we got 16byte end symbol */
  int enc = ctx->encrypt;
  int size;	// the char num we write to fd, multiple of 512
  int ret;
  size = ((len + 32) % 512) == 0 ? (len+32) : (((len+32) >> 9) + 1) << 9;
  memset(tmp_in, 0, MY_DATA_LEN);	// 8K + 32 instruct code + 480 padding
  if (1 == enc) {		// encryption
    tmp_in->con[0] = 0x12345678;
    tmp_in->con[4] = 0x55;
    tmp_in->con[5] = len;
    tmp_in->con[6] = 0x1111;
    tmp_in->con[7] = 0x2222;
    
    memcpy(tmp_in->msg, in, len);
    lseek(fd, 0, SEEK_SET);
    ret = write(fd, tmp_in, MY_DATA_LEN);
    fsync(fd);

    lseek(fd, 0, SEEK_SET);
    read(fd, tmp_in, MY_DATA_LEN);
    fsync(fd);

    memcpy(out, tmp_in->msg, len);
  } else if (0 == enc) {	// decryption
    tmp_in->con[0] = 0x12345678;
    tmp_in->con[4] = 0xaa;
    tmp_in->con[5] = len;
    tmp_in->con[6] = 0x1111;
    tmp_in->con[7] = 0x2222;

    memcpy(tmp_in->msg, in, len);
    lseek(fd, 0, SEEK_SET);
    write(fd, tmp_in, MY_DATA_LEN);
    fsync(fd);

    lseek(fd, 0, SEEK_SET);
    read(fd, tmp_in, MY_DATA_LEN);
    fsync(fd);

    memcpy(out, tmp_in->msg, len);
  } else {
    fprintf(stderr, "Should not be here\n");
    return 0;
  }

  return 1;		  
}

#endif
