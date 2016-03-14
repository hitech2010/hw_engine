/*
 * hw_rand.c
 * Originally written by Zhao Junwang<zhjwpku@gmail.com> for the cryptop 
 * safemodule.
 */

#include <openssl/evp.h>
#include <string.h>
#include <openssl/rand.h>
#include <common.h>

#if IS_CRYPTOP

static int seed(const void *buf, int num);
static int bytes(unsigned char *buf, int num);
static void cleanup(void);
static int add(const void *buf, int num, double entropy);
static int pseudorand(unsigned char *buf, int num);
static int status(void);

// The engine calls this function to initial RAND_METHOD
void engine_rand_init(RAND_METHOD *hw_rand)
{
  memcpy(hw_rand, RAND_get_rand_method(), sizeof(RAND_METHOD));
}

// The implementatitons
static int seed(const void *buf, int num)
{
  return 1;
}

static int bytes(unsigned char *buf, int num)
{
  return 1;
}

static void cleanup(void){
}

static int add(const void *buf, int num, double entropy)
{
  return 1;
}

static int pseudorand(unsigned char *buf, int num)
{
  return 1;
}

static int status(void)
{
  return 1;
}
#endif
