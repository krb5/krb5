/*
 * lib/krb5/keytab/srvtab/kts_util.c
 *
 * Copyright (c) Hewlett-Packard Company 1991
 * Released to the Massachusetts Institute of Technology for inclusion
 * in the Kerberos source code distribution.
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
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
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * This function contains utilities for the srvtab based implementation
 * of the keytab.  There are no public functions in this file.
 */

#define NEED_SOCKETS
#include "krb5.h"
#include "k5-int.h"
#include <stdio.h>

#include "ktsrvtab.h"

#ifdef ANSI_STDIO
#define		READ_MODE	"rb"
#else
#define		READ_MODE	"r"
#endif

/* The maximum sizes for V4 aname, realm, sname, and instance +1 */
/* Taken from krb.h */
#define 	ANAME_SZ	40
#define		REALM_SZ	40
#define		SNAME_SZ	40
#define		INST_SZ		40

#ifndef HAVE_ERRNO
extern int errno;
#endif

static krb5_error_code
read_field(fp, s, len)
    FILE *fp;
    char *s;
    int len;
{
    int c, n = 0;

    while ((c = getc(fp)) != 0) {
	if (c == EOF || len <= 1)
	    return KRB5_KT_END;
	*s = c;
	s++;
	len--;
    }
    *s = 0;
    return 0;
}

krb5_error_code
krb5_ktsrvint_open(context, id)
    krb5_context context;
    krb5_keytab id;
{
    KTFILEP(id) = fopen(KTFILENAME(id), READ_MODE);
    if (!KTFILEP(id))
	return errno;
    return 0;
}

krb5_error_code
krb5_ktsrvint_close(context, id)
    krb5_context context;
    krb5_keytab id;
{
    if (!KTFILEP(id))
	return 0;
    (void) fclose(KTFILEP(id));
    KTFILEP(id) = 0;
    return 0;
}

krb5_error_code
krb5_ktsrvint_read_entry(context, id, ret_entry)
    krb5_context context;
    krb5_keytab id;
    krb5_keytab_entry *ret_entry;
{
    FILE *fp;
    char name[SNAME_SZ], instance[INST_SZ], realm[REALM_SZ];
    unsigned char key[8];
    int vno;
    krb5_error_code kerror;

    /* Read in an entry from the srvtab file. */
    fp = KTFILEP(id);
    kerror = read_field(fp, name, sizeof(name));
    if (kerror != 0)
	return kerror;
    kerror = read_field(fp, instance, sizeof(instance));
    if (kerror != 0)
	return kerror;
    kerror = read_field(fp, realm, sizeof(realm));
    if (kerror != 0)
	return kerror;
    vno = getc(fp);
    if (vno == EOF)
	return KRB5_KT_END;
    if (fread(key, 1, sizeof(key), fp) != sizeof(key))
	return KRB5_KT_END;

    /* Fill in ret_entry with the data we read.  Everything maps well
     * except for the timestamp, which we don't have a value for.  For
     * now we just set it to 0. */
    memset(ret_entry, 0, sizeof(*ret_entry));
    ret_entry->magic = KV5M_KEYTAB_ENTRY;
    kerror = krb5_425_conv_principal(context, name, instance, realm,
				     &ret_entry->principal);
    if (kerror != 0)
	return kerror;
    ret_entry->vno = vno;
    ret_entry->timestamp = 0;
    ret_entry->key.enctype = ENCTYPE_DES_CBC_CRC;
    ret_entry->key.magic = KV5M_KEYBLOCK;
    ret_entry->key.length = sizeof(key);
    ret_entry->key.contents = malloc(sizeof(key));
    if (!ret_entry->key.contents) {
	krb5_free_principal(context, ret_entry->principal);
	return ENOMEM;
    }
    memcpy(ret_entry->key.contents, key, sizeof(key));

    return 0;
}
