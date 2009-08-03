/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 * 
 * All rights reserved.
 * 
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#ifndef CKSUMTYPES_H
#define CKSUMTYPES_H
#include "k5-int.h"

struct krb5_cksumtypes {
    krb5_cksumtype ctype;
    unsigned int flags;
    char *name;
    char *aliases[2];
    char *out_string;
    /* if the hash is keyed, this is the etype it is keyed with.
       Actually, it can be keyed by any etype which has the same
       enc_provider as the specified etype.  DERIVE checksums can
       be keyed with any valid etype. */
    krb5_enctype keyed_etype;
    /* I can't statically initialize a union, so I'm just going to use
       two pointers here.  The keyhash is used if non-NULL.  If NULL,
       then HMAC/hash with derived keys is used if the relevant flag
       is set.  Otherwise, a non-keyed hash is computed.  This is all
       kind of messy, but so is the krb5 api. */
    const struct krb5_keyhash_provider *keyhash;
    const struct krb5_hash_provider *hash;
    /* This just gets uglier and uglier.  In the key derivation case,
       we produce an hmac.  To make the hmac code work, we can't hack
       the output size indicated by the hash provider, but we may want
       a truncated hmac.  If we want truncation, this is the number of
       bytes we truncate to; it should be 0 otherwise.  */
    unsigned int trunc_size;
};

#define KRB5_CKSUMFLAG_DERIVE		0x0001
#define KRB5_CKSUMFLAG_NOT_COLL_PROOF	0x0002

extern const struct krb5_cksumtypes krb5_cksumtypes_list[];
extern const unsigned int krb5_cksumtypes_length;
#endif
