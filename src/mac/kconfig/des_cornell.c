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


/*
 * Des stub routines to use DES routines from Cornell's Kdriver.
 */

#ifdef TN3270
#pragma segment 3270tcp
#define bzero xbzero
#endif

#ifdef NCSA
#pragma segment 22
#define bzero xbzero
#endif
 
#include <Devices.h>
#include <Files.h>
#include <Traps.h>
#include <SysEqu.h>

#include "krb_driver.h"
#include "glue.h"
#include "encrypt.h"
#include "desproto.h"

void bzero(void *, long);

static short kdriver = 0;		/* .Kerberos driver ref */
long driverA4;					/* a4 in driver environment */

long (*c_des_new_random_key)(des_cblock key) = 0;
long (*c_des_ecb_encrypt)(unsigned long *clear, unsigned long *cipher, des_key_schedule schedule, long encrypt) = 0;
long (*c_des_set_random_generator_seed)(des_cblock *key) = 0;
long (*c_des_key_sched)(des_cblock k, des_key_schedule schedule) = 0;
void (*c_des_init_random_number_generator)(des_cblock key) = 0;
long (*c_des_pcbc_encrypt)(unsigned char *in, unsigned char * out, register long length,
						des_key_schedule key, unsigned char *iv, long encrypt) = 0;
long (*c_des_string_to_key)(char *str, unsigned char *key) = 0;
unsigned long (*c_des_quad_cksum) (unsigned char *in, unsigned long *out, long length,
							   long out_count, unsigned char *c_seed) = 0;
long (*c_gettimeofdaynet) (struct timeval *tp, struct timezone *tz) = 0;

/*
 * init_cornell_des
 * Returns -2 if no kdriver
 * Returns other error if this kdriver does not have the DES hooks.
 */
long init_cornell_des ()
{
	short s;
	ParamBlockRec pb;
	long addrs[10];
	
	/*
	 * Open the .Kerberos driver if not already open
	 */
	if (!kdriver) {
		if (s = OpenDriver("\p.Kerberos", &kdriver)) {
			return -2;
		}
	}

	bzero(&pb, sizeof(ParamBlockRec));
	((long *)pb.cntrlParam.csParam)[0] = (long)&addrs[0];
	((long *)pb.cntrlParam.csParam)[1] = sizeof(addrs)/sizeof(long);
	pb.cntrlParam.ioCompletion = nil;
	pb.cntrlParam.ioCRefNum = kdriver;

	pb.cntrlParam.csCode = cKrbGetDesPointers;
	if (s = PBControl(&pb, false))
		return s;
	if (s = pb.cntrlParam.ioResult)
		return s;

	driverA4 = addrs[0];
	c_des_new_random_key = (long(*)()) addrs[1];
	c_des_ecb_encrypt = (long(*)()) addrs[2];
	c_des_set_random_generator_seed = (long(*)()) addrs[3];
	c_des_key_sched = (long(*)()) addrs[4];
	c_des_init_random_number_generator = (void(*)()) addrs[5];
	c_des_pcbc_encrypt = (long(*)()) addrs[6];
	c_des_string_to_key = (long(*)()) addrs[7];
	c_des_quad_cksum = (unsigned long(*)()) addrs[8];
	c_gettimeofdaynet = (long(*)()) addrs[9];

	return 0;
}


long des_new_random_key(des_cblock key)
{
	long oldA4;
	long s = 0;
	
	if (c_des_new_random_key) {
		oldA4 = swapA4(driverA4);
		s = (*c_des_new_random_key)(key);
		swapA4(oldA4);
	}
	return s;
}


long des_ecb_encrypt(unsigned long *clear, unsigned long *cipher, des_key_schedule schedule, long encrypt)
{
	long oldA4;
	long s = 0;
	
	if (c_des_ecb_encrypt) {
		oldA4 = swapA4(driverA4);
		s = (*c_des_ecb_encrypt)(clear, cipher, schedule, encrypt);
		swapA4(oldA4);
	}
	return s;
}


long des_set_random_generator_seed(des_cblock *key)
{
	long oldA4;
	long s = 0;

	if (c_des_set_random_generator_seed) {
		oldA4 = swapA4(driverA4);
		s = (*c_des_set_random_generator_seed)(key);
		swapA4(oldA4);
	}
	return s;
}


long des_key_sched(des_cblock k, des_key_schedule schedule)
{
	long oldA4;
	long s = 0;
	
	if (c_des_key_sched) {
		oldA4 = swapA4(driverA4);
		s = (*c_des_key_sched)(k, schedule);
		swapA4(oldA4);
	}
	return s;
}


void des_init_random_number_generator(des_cblock key)
{
	long oldA4;
	
	if (c_des_init_random_number_generator) {
		oldA4 = swapA4(driverA4);
		(*c_des_init_random_number_generator)(key);
		swapA4(oldA4);
	}
}


long des_pcbc_encrypt (unsigned char *in, unsigned char * out, register long length,
						des_key_schedule key, unsigned char *iv, long encrypt)
{
	long oldA4, s = 0;
	
	if (c_des_pcbc_encrypt) {
		oldA4 = swapA4(driverA4);
		s = (*c_des_pcbc_encrypt)(in, out, length, key, iv, encrypt);
		swapA4(oldA4);
	}
	return s;
}


long des_string_to_key (char *str, unsigned char *key)
{
	long oldA4, s = 0;
	
	if (c_des_string_to_key) {
		oldA4 = swapA4(driverA4);
		s = (*c_des_string_to_key)(str, key);
		swapA4(oldA4);
	}
	return s;
}

unsigned long des_quad_cksum (unsigned char *in, unsigned long *out, long length,
							   long out_count, unsigned char *c_seed)
{
	long oldA4;
	unsigned long s = 0;
	
	if (c_des_quad_cksum) {
		oldA4 = swapA4(driverA4);
		s = (*c_des_quad_cksum)(in, out, length, out_count, c_seed);
		swapA4(oldA4);
	}
	return s;
}


long gettimeofdaynet (struct timeval *tp, struct timezone *tz)
{
	long oldA4, s = 0;
	
	if (c_gettimeofdaynet) {
		oldA4 = swapA4(driverA4);
		s = (*c_gettimeofdaynet)(tp, tz);
		swapA4(oldA4);
	}
	return s;
}
