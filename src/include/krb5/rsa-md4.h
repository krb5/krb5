/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * Definitions for the MD4 checksum.
 */

/*
 * md4.h from RFC1186
 *
 * $Log$
 * Revision 5.2  1990/11/20 10:23:54  jtkohl
 * don't need types defined here, see <encryption.h>
 *
 * Revision 5.1  90/11/08  11:30:49  jtkohl
 * add STDC function prototypes
 * add declaration of MDreverse
 * add Kerberos V5 additions.
 * 
 * Revision 5.0  90/11/07  14:12:21  jtkohl
 * Initial code from RFC
 * 
 */

#include <krb5/copyright.h>

#ifndef KRB5_RSA_MD4__
#define KRB5_RSA_MD4__

#define RSA_MD4_CKSUM_LENGTH	(4*sizeof(krb5_int32))

extern krb5_checksum_entry rsa_md4_cksumtable_entry;

/*
** ********************************************************************
** md4.h -- Header file for implementation of                        **
** MD4 Message Digest Algorithm                                      **
** Updated: 2/13/90 by Ronald L. Rivest                              **
** (C) 1990 RSA Data Security, Inc.                                  **
** ********************************************************************
*/

#ifdef BITS32
/* MDstruct is the data structure for a message digest computation.
*/
typedef struct {
  unsigned int buffer[4]; /* Holds 4-word result of MD computation */
  unsigned char count[8]; /* Number of bits processed so far */
  unsigned int done;      /* Nonzero means MD computation finished */
} MDstruct, *MDptr;
#else
 error: you gotta fix this implementation to deal with non-32 bit words;
#endif

/* MDbegin(MD)
** Input: MD -- an MDptr
** Initialize the MDstruct prepatory to doing a message digest
** computation.
*/
#ifdef __STDC__
extern void MDbegin(MDptr);
#else
extern void MDbegin();
#endif

/* MDupdate(MD,X,count)
** Input: MD -- an MDptr
**        X -- a pointer to an array of unsigned characters.
**        count -- the number of bits of X to use (an unsigned int).
** Updates MD using the first "count" bits of X.
** The array pointed to by X is not modified.
** If count is not a multiple of 8, MDupdate uses high bits of
** last byte.
** This is the basic input routine for a user.
** The routine terminates the MD computation when count < 512, so
** every MD computation should end with one call to MDupdate with a
** count less than 512.  Zero is OK for a count.
*/
#ifdef __STDC__
extern void MDupdate(MDptr, unsigned char *, unsigned int);
#else
extern void MDupdate();
#endif

/* MDprint(MD)
** Input: MD -- an MDptr
** Prints message digest buffer MD as 32 hexadecimal digits.
** Order is from low-order byte of buffer[0] to high-order byte
** of buffer[3].
** Each byte is printed with high-order hexadecimal digit first.
*/
#ifdef __STDC__
extern void MDprint(MDptr);
#else
extern void MDprint();
#endif

/* MDreverse(X)
** Reverse the byte-ordering of every int in X.
** Assumes X is an array of 16 ints.
*/
#ifdef __STDC__
extern void MDreverse(unsigned int *);
#else
extern void MDreverse();
#endif

/*
** End of md4.h
*/
#endif /* KRB5_RSA_MD4__ */
