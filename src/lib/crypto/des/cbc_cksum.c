/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * Copyright 1985, 1986, 1987, 1988 by the Massachusetts Institute
 * of Technology.
 *
 * Under U.S. law, this software may not be exported outside the US
 * without license from the U.S. Commerce department.
 *
 * These routines form the library interface to the DES facilities.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 */

#if !defined(lint) && !defined(SABER)
static char des_cbc_checksum_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>

#include <sys/errno.h>

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>
#include <krb5/krb5_err.h>

#include <krb5/des.h>

extern void des_cbc_cksum();
extern int des_key_sched();

/*
	produces cbc cheksum of sequence "in" of the length "in_length" 
	with the help of key "key" of size "key_size" (which should be 8);
	fills out krb5_checksum structure.

	caller is responsible for freeing "contents" element in 
	krb5_checksum structure.

	returns: errors
*/
krb5_error_code mit_des_cbc_checksum(DECLARG(krb5_pointer, in),
				     DECLARG(size_t, in_length),
				     DECLARG(krb5_pointer, key),
				     DECLARG(size_t, key_size),
				     DECLARG(krb5_checksum *, cksum))
OLDDECLARG(krb5_pointer, in)
OLDDECLARG(size_t, in_length)
OLDDECLARG(krb5_pointer, key)
OLDDECLARG(size_t, key_size)
OLDDECLARG(krb5_checksum *, cksum)
{
    struct des_ks_struct       *schedule;      /* pointer to key schedules */
    krb5_octet 	*contents;

    if (key_size != sizeof(des_cblock))
	return -1;

    if (!(schedule = (struct des_ks_struct *) malloc(sizeof(des_key_schedule))))
        return ENOMEM;

#define cleanup() { bzero((char *)schedule, sizeof(des_key_schedule));\
		    free( (char *) schedule); }

    switch (des_key_sched ((krb5_octet *)key, schedule)) {
    case -1:
        cleanup();
        return KRB5DES_BAD_KEYPAR;       /* XXX error code-bad key parity */

    case -2:
        cleanup();
        return KRB5DES_WEAK_KEY;       /* XXX error code-weak key */

    default:
        ;
    }

    if (!(contents = (krb5_octet *) malloc(sizeof(des_cblock))))
        return ENOMEM;

#define cleanup2() { free( (char *) schedule); }

    des_cbc_cksum((krb5_octet *)in, contents, in_length,
		  schedule, (krb5_octet *)key);

    cksum->checksum_type = CKSUMTYPE_DESCBC;
    cksum->length = sizeof(des_cblock);
    cksum->contents = contents;
    cleanup();

    return 0;
}
    
