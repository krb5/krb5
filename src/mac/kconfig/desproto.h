/*
 * Copyright 1991-1994 by The University of Texas at Austin
 * All rights reserved.
 *
 * For infomation contact:
 * Rick Watson
 * University of Texas
 * Computation Center, COM 1
 * Austin, TX 78712
 * r.watson@utexas.edu
 * 512-471-3241
 */

struct timeval {
	long tv_sec;
	long tv_usec;
};

struct timezone {
	long dummy;
};

extern long init_cornell_des(void);
extern long des_new_random_key(des_cblock key);
extern long des_ecb_encrypt(unsigned long *clear, unsigned long *cipher, des_key_schedule schedule, long encrypt);
extern long des_set_random_generator_seed(des_cblock *key);
extern long des_key_sched(des_cblock k, des_key_schedule schedule);
extern void des_init_random_number_generator(des_cblock key);
extern long des_pcbc_encrypt(unsigned char *in, unsigned char * out, register long length,
						des_key_schedule key, unsigned char *iv, long encrypt);
extern long des_string_to_key(char *str, unsigned char *key);
extern unsigned long des_quad_cksum (unsigned char *in, unsigned long *out, long length,
							   long out_count, unsigned char *c_seed);
long gettimeofdaynet(struct timeval *tp, struct timezone *tz);
