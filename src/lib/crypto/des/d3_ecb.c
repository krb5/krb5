/*
 * Copyright 1995 by Richard P. Basch.  All Rights Reserved.
 * Copyright 1995 by Lehman Brothers, Inc.  All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of Richard P. Basch, Lehman Brothers and M.I.T. not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission.  Richard P. Basch,
 * Lehman Brothers and M.I.T. make no representations about the suitability
 * of this software for any purpose.  It is provided "as is" without
 * express or implied warranty.
 */

#include "des.h"
#include "des_int.h"
#include "f_tables.h"

/*
 * Triple-DES ECB encryption mode.
 */

int
mit_des3_ecb_encrypt(in, out, sched1, sched2, sched3, encrypt)
	const mit_des_cblock FAR *in;
	mit_des_cblock FAR *out;
	mit_des_key_schedule sched1, sched2, sched3;
	int encrypt;
{
	if (encrypt) {
		mit_des_ecb_encrypt(in, out, sched1, encrypt);
		mit_des_ecb_encrypt(out, out, sched2, !encrypt);
		mit_des_ecb_encrypt(out, out, sched3, encrypt);
	} else {
		mit_des_ecb_encrypt(in, out, sched3, encrypt);
		mit_des_ecb_encrypt(out, out, sched2, !encrypt);
		mit_des_ecb_encrypt(out, out, sched1, encrypt);
	}
	return 0;
}
