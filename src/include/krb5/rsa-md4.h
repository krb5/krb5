/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * RSA MD4 header file, with Kerberos/STDC additions.
 */

#ifndef __KRB5_RSA_MD4_H__
#define __KRB5_RSA_MD4_H__

/* 4 words of buffer, plus 8 bytes of count */
#define RSA_MD4_CKSUM_LENGTH	(4*sizeof(krb5_int32)+8)
#define RSA_MD4_DES_CKSUM_LENGTH	(4*sizeof(krb5_int32)+8)

extern krb5_checksum_entry
    rsa_md4_cksumtable_entry,
    rsa_md4_des_cksumtable_entry;

/*
 **********************************************************************
 ** md4.h -- Header file for implementation of MD4                   **
 ** RSA Data Security, Inc. MD4 Message Digest Algorithm             **
 ** Created: 2/17/90 RLR                                             **
 ** Revised: 12/27/90 SRD,AJ,BSK,JT Reference C version              **
 **********************************************************************
 */

/*
 **********************************************************************
 ** Copyright (C) 1990, RSA Data Security, Inc. All rights reserved. **
 **                                                                  **
 ** License to copy and use this software is granted provided that   **
 ** it is identified as the "RSA Data Security, Inc. MD4 Message     **
 ** Digest Algorithm" in all material mentioning or referencing this **
 ** software or this function.                                       **
 **                                                                  **
 ** License is also granted to make and use derivative works         **
 ** provided that such works are identified as "derived from the RSA **
 ** Data Security, Inc. MD4 Message Digest Algorithm" in all         **
 ** material mentioning or referencing the derived work.             **
 **                                                                  **
 ** RSA Data Security, Inc. makes no representations concerning      **
 ** either the merchantability of this software or the suitability   **
 ** of this software for any particular purpose.  It is provided "as **
 ** is" without express or implied warranty of any kind.             **
 **                                                                  **
 ** These notices must be retained in any copies of any part of this **
 ** documentation and/or software.                                   **
 **********************************************************************
 */

#ifdef BITS32
/* typedef a 32 bit type */
typedef unsigned long int UINT4;
#else
 error: you gotta fix this implementation to deal with non-32 bit words;
#endif

/* Data structure for MD4 (Message Digest) computation */
typedef struct {
  UINT4 i[2];                   /* number of _bits_ handled mod 2^64 */
  UINT4 buf[4];                                    /* scratch buffer */
  unsigned char in[64];                              /* input buffer */
  unsigned char digest[16];     /* actual digest after MD4Final call */
} MD4_CTX;

#ifdef __STDC__
extern void MD4Init(MD4_CTX *);
extern void MD4Update(MD4_CTX *, unsigned char *, unsigned int);
extern void MD4Final(MD4_CTX *);
#else
void MD4Init ();
void MD4Update ();
void MD4Final ();
#endif

/*
 **********************************************************************
 ** End of md4.h                                                     **
 ******************************* (cut) ********************************
 */
#endif /* __KRB5_RSA_MD4_H__ */
