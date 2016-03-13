#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>

#define CRYPTOP_BASE	0xC0900000
#define CRYPTOP_SIZE	0x80000

#define HASH_RF_BASE  (reg_base)

#define __REG(x)  (*(unsigned int *)(x))

#define REG_MODE	__REG(reg_base + 0x248*4)
#define REG_R_ISRAM	__REG(reg_base + 0x244*4)
#define REG_W_ISRAM	__REG(reg_base + 0x244*4)
#define REG_RUN_ISRAM	__REG(reg_base + 0x244*4)
#define REG_I_PORT	__REG(reg_base + 0x246*4)

#define REG_R_DSRAM	__REG(reg_base + 0x249*4)
#define REG_W_DSRAM	__REG(reg_base + 0x249*4)
#define REG_D_PORT	__REG(reg_base + 0x24a*4)

#define REG_TRANS_LOW	__REG(reg_base + 0x200*4)
#define REG_TRANS_HIG	__REG(reg_base + 0x201*4)


#define REG_HASH_RF_HIG	__REG(reg_base + 0x262*4)
#define REG_HASH_RF_LOW	__REG(reg_base + 0x261*4)

#define REG_W_SR	__REG(reg_base + 0x248*4)


#define TRANS_LOW(sram_rf_d,addr_d,len) ((((len)&0x1ff) <<21)  \
		    | (((sram_rf_d)&0x1) <<19) | (((addr_d)&0x7ff) <<8))
#define TRANS_HIG(sram_rf_s,addr_s) ((((sram_rf_s)&0x1) <<19) | (((addr_s)&0x7ff) <<8) \
		    |(0x7<<27))

#define R_ISRAM(base_addr,inst_num)  ((((base_addr)&0x3ff)<<16) | (((inst_num)&0x3ff) <<4) \
		    | 0xc)
#define W_ISRAM(base_addr,inst_num)  ((((base_addr)&0x3ff)<<16) | (((inst_num)&0x3ff) <<4) \
		    | 0xe)

#define R_DSRAM(base_addr,num)  ((((base_addr)&0x7ff) <<16) | (((num)&0x7ff) <<4) | 0xc)
#define W_DSRAM(base_addr,num)  ((((base_addr)&0x7ff) <<16) | (((num)&0x7ff) <<4) | 0xe)

#define RUN_ISRAM(base_addr,inst_num,change_config) ((((base_addr)&0x3ff)<<16) \
		    | (((inst_num)&0x3ff)<<4) | (((change_config)&0x1)<<3) | (0x5))

#define HASH_RF_HIG(addr_d,addr_s) ((((addr_d)&0x1ff)<<9) |((addr_s)&0x1ff) |(0x3<<18))
#define HASH_RF_LOW(last_block,block_len,alg) ((((last_block)&0x1)<<14) \
		    |(((block_len)&0x3ff)<<4) |(((alg)&0x3)<<2) |(0xf<<28))

#define W_SR_HIG(cond_reg,cond_code,cond,reg_code,RIMM,addr) ((((cond_reg)&0x1)<<23) \
		    | (((cond_code)&0xf) <<19) |(((cond)&0x1)<<18) |(((reg_code)&0xf)<<14) \
		    | (((RIMM)&0x7)<<11) |((addr)&0x3f) | (0x51<<24))

#define W_SR_LOW(imm)	(imm)

#define ALG_SM3		0x0
#define ALG_SHA256	0x1
#define ALG_SHA160	0x2

int main()
{
  int fd = -1;
  int i = 0,j;
  unsigned int reg_base = 0;
  unsigned char buff[2048];

  fd = open("/dev/mem", O_RDWR | O_SYNC);
  if (fd < 0) {
    fprintf(stderr, "cannot open /dev/mem\n");
    return -1;
  }

  reg_base = (unsigned int) mmap(NULL, CRYPTOP_SIZE, PROT_READ | PROT_WRITE |
				 MAP_FIXED, MAP_SHARED, fd, CRYPTOP_BASE);
  if (reg_base == (unsigned int) MAP_FAILED) {
    reg_base = 0;
    fprintf(stderr, "mmap cryptop error\n");
    close(fd);
    return -1;
  }
#if 0
  for(i=0;i<256;i++) {
    memset(buff+8*i,i,8);
  }
  memcpy((char *)reg_base,buff,2048);

  REG_W_DSRAM = W_DSRAM(0,511); //W_DSRAM
  REG_TRANS_LOW =TRANS_LOW(1,0,511);
  REG_TRANS_HIG = TRANS_HIG(0,0);

  sleep(1);
  REG_R_DSRAM = R_DSRAM(0,511); //R_DSRAM
  printf("read data : \n");
  for(i=0;i<512;i++) {
    printf("%x\n", REG_D_PORT);
  }

  for(i=0;i<100;i++) {
    buff[i] = 0x80+i;
  }
  memcpy((char *)reg_base,buff,100);

  REG_W_ISRAM = W_ISRAM(0,0xc); //W_ISRAM
  REG_TRANS_LOW = TRANS_LOW(1,0,0xc);
  REG_TRANS_HIG = TRANS_HIG(0,0);

  sleep(2);

  REG_R_ISRAM = R_ISRAM(0,0xc);//R_ISRAM
  printf("%x \n",R_ISRAM(0,0xc));

  printf("read instruction : \n");
  for(i=0;i<12;i++) {  
    printf("%x\n", REG_I_PORT);
  }

  sleep(3);

  REG_R_DSRAM = R_DSRAM(0,0xf);
  printf("read data for cmp : \n");
  for(i=0;i<20;i++) {  
    printf("%x\n", REG_D_PORT);
  }

 // REG_RUN_ISRAM = RUN_ISRAM(0x0,0xf,1); //RUN_ISRAM
#endif
  printf("HASH RF Test Begin \n");

  memset((void*)HASH_RF_BASE,0x30,2048);
  
//  for(i=0;i<8;i++) {
//  REG_MODE = 0x10+i;

  REG_HASH_RF_HIG = HASH_RF_HIG(0x0,8);
  REG_HASH_RF_LOW = HASH_RF_LOW(1,8,ALG_SHA160);

  REG_MODE = 0x18;
  

  
  printf("mode:%x, RF_HIG:%x, RF_LOW:%x \n",REG_MODE,REG_HASH_RF_HIG,REG_HASH_RF_LOW);
  printf("mode:%x, RF_HIG:%x, RF_LOW:%x \n",REG_MODE,HASH_RF_HIG(0x0,8),HASH_RF_LOW(1,8,ALG_SHA160));
  sleep(3);
  
  for(j=0;j<8;j++)
    printf("%x ",__REG(reg_base+4*j));

  printf("\ncmp ..... \n");
  for(j=0;j<8;j++)
    printf("%x ",__REG(reg_base+(289+j)*4));

   printf(".....%x \n",__REG(reg_base+(280+j)*4));


  printf("\n");

 /// }
  if (reg_base)
    munmap((void *)reg_base, CRYPTOP_SIZE);

  if (fd > 0)
    close(fd);
  
  return 0;

}
