/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1989 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * Header file for some glue functions (macros, mostly)
 */

#include <krb5/copyright.h>

#ifndef __KRB5_GLUE_H__
#define __KRB5_GLUE_H__

#define krb5_string2qbuf(val) str2qb((val)->string, (val)->length, 1)

#define krb5_kdcoptions2KRB5_KDCOptions(val, err) (struct type_KRB5_KDCOptions *)krb5_flags2KRB5_TicketFlags(val, err)
#define KRB5_KDCOptions2krb5_kdcoptions(val, err) KRB5_TicketFlags2krb5_flags((struct type_KRB5_TicketFlags *) (val), err)
#define krb5_apoptions2KRB5_APOptions(val, err) (struct type_KRB5_APOptions *)krb5_flags2KRB5_TicketFlags(val, err)
#define KRB5_APOptions2krb5_apoptions(val, err) KRB5_TicketFlags2krb5_flags((struct type_KRB5_APOptions *) (val), err)

#define free_krb5_string(val) { xfree((val)->string); xfree(val);}

#define free_krb5_ap_rep_enc_part xfree
#define free_krb5_checksum xfree
#define free_krb5_keyblock xfree

/* to keep lint happy */
#define xfree(val) free((char *)(val))
#define xbcopy(src,dst,size) bcopy((char *)(src), (char *)(dst), size)
#define xbzero(targ, size) bzero((char *)(targ), size)
#define xmalloc(n) malloc((unsigned) (n))
#define xcalloc(n,s) calloc((unsigned)(n), (unsigned)(s))

#endif /* __KRB5_GLUE_H__ */
