/*
 * lib/krb5/keytab/file/ktf_util.c
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
 * This function contains utilities for the file based implementation of 
 * the keytab.  There are no public functions in this file.
 *
 * This file is the only one that has knowledge of the format of a
 * keytab file.
 *
 * The format is as follows:
 * 
 * <file format vno>
 * <record length>
 * principal timestamp vno key
 * <record length>
 * principal timestamp vno key
 * ....
 *
 * A length field (sizeof(krb5_int32)) exists between entries.  When this
 * length is positive it indicates an active entry, when negative a hole.
 * The length indicates the size of the block in the file (this may be 
 * larger than the size of the next record, since we are using a first
 * fit algorithm for re-using holes and the first fit may be larger than
 * the entry we are writing).  Another (compatible) implementation could
 * break up holes when allocating them to smaller entries to minimize 
 * wasted space.  (Such an implementation should also coalesce adjacent
 * holes to reduce fragmentation).  This implementation does neither.
 *
 * There are no separators between fields of an entry.  
 * A principal is a length-encoded array of length-encoded strings.  The
 * length is a krb5_int16 in each case.  The specific format, then, is 
 * multiple entries concatinated with no separators.  An entry has this 
 * exact format:
 *
 * sizeof(krb5_int16) bytes for number of components in the principal; 
 * then, each component listed in ordser.
 * For each component, sizeof(krb5_int16) bytes for the number of bytes
 * in the component, followed by the component.
 * sizeof(krb5_int32) for the principal type (for KEYTAB V2 and higher)
 * sizeof(krb5_int32) bytes for the timestamp
 * sizeof(krb5_octet) bytes for the key version number
 * sizeof(krb5_int16) bytes for the enctype
 * sizeof(krb5_int32) bytes for the key length, followed by the key
 */

#define NEED_SOCKETS
#include "krb5.h"
#include "k5-int.h"
#include <stdio.h>

#include "ktfile.h"

#ifndef SEEK_SET
#define SEEK_SET 0
#define SEEK_CUR 1
#endif

typedef krb5_int16  krb5_kt_vno;

krb5_kt_vno krb5_kt_default_vno = KRB5_KT_DEFAULT_VNO;

#define xfwrite(a, b, c, d) fwrite((char *)a, b, c, d)
#define xfread(a, b, c, d) fread((char *)a, b, c, d)

#ifdef ANSI_STDIO
static char *fopen_mode_rbplus= "rb+";
static char *fopen_mode_rb = "rb";
#else
static char *fopen_mode_rbplus= "r+";
static char *fopen_mode_rb = "r";
#endif

#ifndef HAVE_ERRNO
extern int errno;
#endif

static krb5_error_code
krb5_ktfileint_open(context, id, mode)
    krb5_context context;
krb5_keytab id;
int mode;
{
    krb5_error_code kerror;
    krb5_kt_vno kt_vno;
    int writevno = 0;

    KTFILEP(id) = fopen(KTFILENAME(id),
			(mode == KRB5_LOCKMODE_EXCLUSIVE) ?
			  fopen_mode_rbplus : fopen_mode_rb);
    if (!KTFILEP(id)) {
	if ((mode == KRB5_LOCKMODE_EXCLUSIVE) && (errno == ENOENT)) {
	    /* try making it first time around */
            krb5_create_secure_file(context, KTFILENAME(id));
	    KTFILEP(id) = fopen(KTFILENAME(id), fopen_mode_rbplus);
	    if (!KTFILEP(id))
		return errno;
	    writevno = 1;
	} else				/* some other error */
	    return errno;
    }
    if ((kerror = krb5_lock_file(context, fileno(KTFILEP(id)), mode))) {
	(void) fclose(KTFILEP(id));
	KTFILEP(id) = 0;
	return kerror;
    }
    /* assume ANSI or BSD-style stdio */
    setbuf(KTFILEP(id), NULL);

    /* get the vno and verify it */
    if (writevno) {
	kt_vno = htons(krb5_kt_default_vno);
	KTVERSION(id) = krb5_kt_default_vno;
	if (!xfwrite(&kt_vno, sizeof(kt_vno), 1, KTFILEP(id))) {
	    kerror = errno;
	    (void) krb5_unlock_file(context, fileno(KTFILEP(id)));
	    (void) fclose(KTFILEP(id));
	    return kerror;
	}
    } else {
	/* gotta verify it instead... */
	if (!xfread(&kt_vno, sizeof(kt_vno), 1, KTFILEP(id))) {
	    kerror = errno;
	    (void) krb5_unlock_file(context, fileno(KTFILEP(id)));
	    (void) fclose(KTFILEP(id));
	    return kerror;
	}
	kt_vno = KTVERSION(id) = ntohs(kt_vno);
	if ((kt_vno != KRB5_KT_VNO) &&
	    (kt_vno != KRB5_KT_VNO_1)) {
	    (void) krb5_unlock_file(context, fileno(KTFILEP(id)));
	    (void) fclose(KTFILEP(id));
	    return KRB5_KEYTAB_BADVNO;
	}
    }
    return 0;
}

krb5_error_code
krb5_ktfileint_openr(context, id)
    krb5_context context;
krb5_keytab id;
{
    return krb5_ktfileint_open(context, id, KRB5_LOCKMODE_SHARED);
}

krb5_error_code
krb5_ktfileint_openw(context, id)
    krb5_context context;
krb5_keytab id;
{
    return krb5_ktfileint_open(context, id, KRB5_LOCKMODE_EXCLUSIVE);
}

krb5_error_code
krb5_ktfileint_close(context, id)
    krb5_context context;
krb5_keytab id;
{
    krb5_error_code kerror;

    if (!KTFILEP(id))
	return 0;
    kerror = krb5_unlock_file(context, fileno(KTFILEP(id)));
    (void) fclose(KTFILEP(id));
    KTFILEP(id) = 0;
    return kerror;
}

krb5_error_code
krb5_ktfileint_delete_entry(context, id, delete_point)
    krb5_context context;
krb5_keytab id;
krb5_int32 delete_point;
{
    krb5_int32  size;
    krb5_int32  len;
    char        iobuf[BUFSIZ];

    if (fseek(KTFILEP(id), delete_point, SEEK_SET)) {
        return errno;
    }
    if (!xfread(&size, sizeof(size), 1, KTFILEP(id))) {
        return KRB5_KT_END;
    }
    if (KTVERSION(id) != KRB5_KT_VNO_1)
	size = ntohl(size);

    if (size > 0) {
        krb5_int32 minus_size = -size;
	if (KTVERSION(id) != KRB5_KT_VNO_1)
	    minus_size = htonl(minus_size);

        if (fseek(KTFILEP(id), delete_point, SEEK_SET)) {
            return errno;
        }

        if (!xfwrite(&minus_size, sizeof(minus_size), 1, KTFILEP(id))) {
            return KRB5_KT_IOERR;
        }

        if (size < BUFSIZ) {
            len = size;
        } else {
            len = BUFSIZ;
        }

        memset(iobuf, 0, (size_t) len);
        while (size > 0) {
            xfwrite(iobuf, 1, (size_t) len, KTFILEP(id));
            size -= len;
            if (size < len) {
                len = size;
            }
        }

        return krb5_sync_disk_file(context, KTFILEP(id));
    }

    return 0;
}

krb5_error_code
krb5_ktfileint_internal_read_entry(context, id, ret_entry, delete_point)
    krb5_context context;
krb5_keytab id;
krb5_keytab_entry *ret_entry;
krb5_int32 *delete_point;
{
    krb5_octet vno;
    krb5_int16 count;
    krb5_int16 enctype;
    krb5_int16 princ_size;
    register int i;
    krb5_int32 size;
    krb5_int32 start_pos;
    krb5_error_code error;
    char	*tmpdata;
    krb5_data	*princ;

    memset(ret_entry, 0, sizeof(krb5_keytab_entry));
    ret_entry->magic = KV5M_KEYTAB_ENTRY;

    /* fseek to synchronise buffered I/O on the key table. */

    if (fseek(KTFILEP(id), 0L, SEEK_CUR) < 0)
    {
        return errno;
    }

    do {
        *delete_point = ftell(KTFILEP(id));
        if (!xfread(&size, sizeof(size), 1, KTFILEP(id))) {
            return KRB5_KT_END;
        }
	if (KTVERSION(id) != KRB5_KT_VNO_1)
		size = ntohl(size);

        if (size < 0) {
            if (fseek(KTFILEP(id), -size, SEEK_CUR)) {
                return errno;
            }
        }
    } while (size < 0);

    if (size == 0) {
        return KRB5_KT_END;
    }

    start_pos = ftell(KTFILEP(id));

    /* deal with guts of parsing... */

    /* first, int16 with #princ components */
    if (!xfread(&count, sizeof(count), 1, KTFILEP(id)))
	return KRB5_KT_END;
    if (KTVERSION(id) == KRB5_KT_VNO_1) {
	    count -= 1;		/* V1 includes the realm in the count */
    } else {
	    count = ntohs(count);
    }
    if (!count || (count < 0))
	return KRB5_KT_END;
    ret_entry->principal = (krb5_principal)malloc(sizeof(krb5_principal_data));
    if (!ret_entry->principal)
        return ENOMEM;
    
    ret_entry->principal->magic = KV5M_PRINCIPAL;
    ret_entry->principal->length = count;
    ret_entry->principal->data = (krb5_data *)calloc(count, sizeof(krb5_data));
    if (!ret_entry->principal->data) {
	free(ret_entry->principal);
	ret_entry->principal = 0;
	return ENOMEM;
    }

    /* Now, get the realm data */
    if (!xfread(&princ_size, sizeof(princ_size), 1, KTFILEP(id))) {
	    error = KRB5_KT_END;
	    goto fail;
    }
    if (KTVERSION(id) != KRB5_KT_VNO_1)
	    princ_size = ntohs(princ_size);
    if (!princ_size || (princ_size < 0)) {
	    error = KRB5_KT_END;
	    goto fail;
    }
    krb5_princ_set_realm_length(context, ret_entry->principal, princ_size);
    tmpdata = malloc(princ_size+1);
    if (!tmpdata) {
	    error = ENOMEM;
	    goto fail;
    }
    if (fread(tmpdata, 1, princ_size, KTFILEP(id)) != (size_t) princ_size) {
	    free(tmpdata);
	    error = KRB5_KT_END;
	    goto fail;
    }
    tmpdata[princ_size] = 0;	/* Some things might be expecting null */
				/* termination...  ``Be conservative in */
				/* what you send out'' */
    krb5_princ_set_realm_data(context, ret_entry->principal, tmpdata);
    
    for (i = 0; i < count; i++) {
	princ = krb5_princ_component(context, ret_entry->principal, i);
	if (!xfread(&princ_size, sizeof(princ_size), 1, KTFILEP(id))) {
	    error = KRB5_KT_END;
	    goto fail;
        }
	if (KTVERSION(id) != KRB5_KT_VNO_1)
	    princ_size = ntohs(princ_size);
	if (!princ_size || (princ_size < 0)) {
	    error = KRB5_KT_END;
	    goto fail;
        }

	princ->length = princ_size;
	princ->data = malloc(princ_size+1);
	if (!princ->data) {
	    error = ENOMEM;
	    goto fail;
        }
	if (!xfread(princ->data, sizeof(char), princ_size, KTFILEP(id))) {
	    error = KRB5_KT_END;
	    goto fail;
        }
	princ->data[princ_size] = 0; /* Null terminate */
    }

    /* read in the principal type, if we can get it */
    if (KTVERSION(id) != KRB5_KT_VNO_1) {
	    if (!xfread(&ret_entry->principal->type,
			sizeof(ret_entry->principal->type), 1, KTFILEP(id))) {
		    error = KRB5_KT_END;
		    goto fail;
	    }
	    ret_entry->principal->type = ntohl(ret_entry->principal->type);
    }
    
    /* read in the timestamp */
    if (!xfread(&ret_entry->timestamp, sizeof(ret_entry->timestamp), 1, KTFILEP(id))) {
	error = KRB5_KT_END;
	goto fail;
    }
    if (KTVERSION(id) != KRB5_KT_VNO_1)
	ret_entry->timestamp = ntohl(ret_entry->timestamp);
    
    /* read in the version number */
    if (!xfread(&vno, sizeof(vno), 1, KTFILEP(id))) {
	error = KRB5_KT_END;
	goto fail;
    }
    ret_entry->vno = (krb5_kvno)vno;
    
    /* key type */
    if (!xfread(&enctype, sizeof(enctype), 1, KTFILEP(id))) {
	error = KRB5_KT_END;
	goto fail;
    }
    ret_entry->key.enctype = (krb5_enctype)enctype;

    if (KTVERSION(id) != KRB5_KT_VNO_1)
	ret_entry->key.enctype = ntohs(ret_entry->key.enctype);
    
    /* key contents */
    ret_entry->key.magic = KV5M_KEYBLOCK;
    
    if (!xfread(&count, sizeof(count), 1, KTFILEP(id))) {
	error = KRB5_KT_END;
	goto fail;
    }
    if (KTVERSION(id) != KRB5_KT_VNO_1)
	count = ntohs(count);
    if (!count || (count < 0)) {
	error = KRB5_KT_END;
	goto fail;
    }
    ret_entry->key.length = count;
    
    ret_entry->key.contents = (krb5_octet *)malloc(count);
    if (!ret_entry->key.contents) {
	error = ENOMEM;
	goto fail;
    }		
    if (!xfread(ret_entry->key.contents, sizeof(krb5_octet), count,
		KTFILEP(id))) {
	error = KRB5_KT_END;
	goto fail;
    }

    /*
     * Reposition file pointer to the next inter-record length field.
     */
    fseek(KTFILEP(id), start_pos + size, SEEK_SET);
    return 0;
fail:
    
    for (i = 0; i < ret_entry->principal->length; i++) {
	    princ = krb5_princ_component(context, ret_entry->principal, i);
	    if (princ->data)
		    free(princ->data);
    }
    free(ret_entry->principal->data);
    ret_entry->principal->data = 0;
    free(ret_entry->principal);
    ret_entry->principal = 0;
    return error;
}

krb5_error_code
krb5_ktfileint_read_entry(context, id, entryp)
    krb5_context context;
krb5_keytab id;
krb5_keytab_entry *entryp;
{
    krb5_int32 delete_point;

    return krb5_ktfileint_internal_read_entry(context, id, entryp, &delete_point);
}

krb5_error_code
krb5_ktfileint_write_entry(context, id, entry)
    krb5_context context;
krb5_keytab id;
krb5_keytab_entry *entry;
{
    krb5_octet vno;
    krb5_data *princ;
    krb5_int16 count, size, enctype;
    krb5_error_code retval = 0;
    krb5_timestamp timestamp;
    krb5_int32	princ_type;
    krb5_int32  size_needed;
    krb5_int32  commit_point;
    int		i;
    char iobuf[BUFSIZ];

    retval = krb5_ktfileint_size_entry(context, entry, &size_needed);
    if (retval)
        return retval;
    retval = krb5_ktfileint_find_slot(context, id, &size_needed, &commit_point);
    if (retval)
        return retval;

    setbuf(KTFILEP(id), iobuf);

    /* fseek to synchronise buffered I/O on the key table. */

    if (fseek(KTFILEP(id), 0L, SEEK_CUR) < 0)
    {
        return errno;
    }

    if (KTVERSION(id) == KRB5_KT_VNO_1) {
	    count = (krb5_int16) entry->principal->length + 1;
    } else {
	    count = htons((u_short) entry->principal->length);
    }
    
    if (!xfwrite(&count, sizeof(count), 1, KTFILEP(id))) {
    abend:
	setbuf(KTFILEP(id), 0);
	return KRB5_KT_IOERR;
    }
    size = krb5_princ_realm(context, entry->principal)->length;
    if (KTVERSION(id) != KRB5_KT_VNO_1)
	    size = htons(size);
    if (!xfwrite(&size, sizeof(size), 1, KTFILEP(id))) {
	    goto abend;
    }
    if (!xfwrite(krb5_princ_realm(context, entry->principal)->data, sizeof(char),
		 krb5_princ_realm(context, entry->principal)->length, KTFILEP(id))) {
	    goto abend;
    }

    count = (krb5_int16) entry->principal->length;
    for (i = 0; i < count; i++) {
	princ = krb5_princ_component(context, entry->principal, i);
	size = princ->length;
	if (KTVERSION(id) != KRB5_KT_VNO_1)
		size = htons(size);
	if (!xfwrite(&size, sizeof(size), 1, KTFILEP(id))) {
	    goto abend;
	}
	if (!xfwrite(princ->data, sizeof(char), princ->length, KTFILEP(id))) {
	    goto abend;
	}
    }

    /*
     * Write out the principal type
     */
    if (KTVERSION(id) != KRB5_KT_VNO_1) {
	    princ_type = htonl(krb5_princ_type(context, entry->principal));
	    if (!xfwrite(&princ_type, sizeof(princ_type), 1, KTFILEP(id))) {
		    goto abend;
	    }
    }
    
    /*
     * Fill in the time of day the entry was written to the keytab.
     */
    if (krb5_timeofday(context, &entry->timestamp)) {
        entry->timestamp = 0;
    }
    if (KTVERSION(id) == KRB5_KT_VNO_1)
	    timestamp = entry->timestamp;
    else
	    timestamp = htonl(entry->timestamp);
    if (!xfwrite(&timestamp, sizeof(timestamp), 1, KTFILEP(id))) {
	goto abend;
    }
    
    /* key version number */
    vno = (krb5_octet)entry->vno;
    if (!xfwrite(&vno, sizeof(vno), 1, KTFILEP(id))) {
	goto abend;
    }
    /* key type */
    if (KTVERSION(id) == KRB5_KT_VNO_1)
	    enctype = entry->key.enctype;
    else
	    enctype = htons(entry->key.enctype);
    if (!xfwrite(&enctype, sizeof(enctype), 1, KTFILEP(id))) {
	goto abend;
    }
    /* key length */
    if (KTVERSION(id) == KRB5_KT_VNO_1)
	    size = entry->key.length;
    else
	    size = htons(entry->key.length);
    if (!xfwrite(&size, sizeof(size), 1, KTFILEP(id))) {
	goto abend;
    }
    if (!xfwrite(entry->key.contents, sizeof(krb5_octet),
		 entry->key.length, KTFILEP(id))) {
	memset(iobuf, 0, sizeof(iobuf));
	setbuf(KTFILEP(id), 0);
	return KRB5_KT_IOERR;
    }	

    retval = krb5_sync_disk_file(context, KTFILEP(id));
    (void) memset(iobuf, 0, sizeof(iobuf));
    setbuf(KTFILEP(id), 0);

    if (retval) {
        return retval;
    }

    if (fseek(KTFILEP(id), commit_point, SEEK_SET)) {
        return errno;
    }
    if (KTVERSION(id) != KRB5_KT_VNO_1)
	    size_needed = htonl(size_needed);
    if (!xfwrite(&size_needed, sizeof(size_needed), 1, KTFILEP(id))) {
        goto abend;
    }
    retval = krb5_sync_disk_file(context, KTFILEP(id));

    return retval;
}

/*
 * Determine the size needed for a file entry for the given
 * keytab entry.
 */
krb5_error_code
krb5_ktfileint_size_entry(context, entry, size_needed)
    krb5_context context;
krb5_keytab_entry *entry;
krb5_int32 *size_needed;
{
    krb5_int16 count;
    krb5_int32 total_size, i;
    krb5_error_code retval = 0;

    count = (krb5_int16) entry->principal->length;
        
    total_size = sizeof(count);
    total_size += krb5_princ_realm(context, entry->principal)->length + (sizeof(krb5_int16));
    
    for (i = 0; i < count; i++) {
	    total_size += krb5_princ_component(context, entry->principal,i)->length
		    + (sizeof(krb5_int16));
    }

    total_size += sizeof(entry->principal->type);
    total_size += sizeof(entry->timestamp);
    total_size += sizeof(krb5_octet);
    total_size += sizeof(krb5_int16);
    total_size += sizeof(krb5_int16) + entry->key.length;

    *size_needed = total_size;
    return retval;
}

/*
 * Find and reserve a slot in the file for an entry of the needed size.
 * The commit point will be set to the position in the file where the
 * the length (sizeof(krb5_int32) bytes) of this node should be written
 * when commiting the write.  The file position left as a result of this
 * call is the position where the actual data should be written.
 *
 * The size_needed argument may be adjusted if we find a hole that is
 * larger than the size needed.  (Recall that size_needed will be used
 * to commit the write, but that this field must indicate the size of the
 * block in the file rather than the size of the actual entry)  
 */
krb5_error_code
krb5_ktfileint_find_slot(context, id, size_needed, commit_point)
    krb5_context context;
krb5_keytab id;
krb5_int32 *size_needed;
krb5_int32 *commit_point;
{
    krb5_int32      size;
    krb5_int32      remainder;
    krb5_int32      zero_point;
    krb5_kt_vno     kt_vno;
    krb5_boolean    found = FALSE;
    char            iobuf[BUFSIZ];

    /*
     * Skip over file version number
     */
    if (fseek(KTFILEP(id), 0, SEEK_SET)) {
        return errno;
    }
    if (!xfread(&kt_vno, sizeof(kt_vno), 1, KTFILEP(id))) {
        return KRB5_KT_IOERR;
    }

    while (!found) {
        *commit_point = ftell(KTFILEP(id));
        if (!xfread(&size, sizeof(size), 1, KTFILEP(id))) {
            /*
             * Hit the end of file, reserve this slot.
             */
            setbuf(KTFILEP(id), 0);
            size = 0;

            /* fseek to synchronise buffered I/O on the key table. */

            if (fseek(KTFILEP(id), 0L, SEEK_CUR) < 0)
            {
                return errno;
            }
	    
#ifdef notdef
	    /* We don't have to do this because htonl(0) == 0 */
	    if (KTVERSION(id) != KRB5_KT_VNO_1)
		    size = htonl(size);
#endif
	    
            if (!xfwrite(&size, sizeof(size), 1, KTFILEP(id))) {
                return KRB5_KT_IOERR;
            }
            found = TRUE;
        }

	if (KTVERSION(id) != KRB5_KT_VNO_1)
		size = ntohl(size);

        if (size > 0) {
            if (fseek(KTFILEP(id), size, SEEK_CUR)) {
                return errno;
            }
        } else if (!found) {
            size = -size;
            if (size >= *size_needed) {
                *size_needed = size;
                found = TRUE;	
            } else if (size > 0) {
                /*
                 * The current hole is not large enough, so skip it
                 */
                if (fseek(KTFILEP(id), size, SEEK_CUR)) {
                    return errno;
                }
            } else {

                 /* fseek to synchronise buffered I/O on the key table. */

                 if (fseek(KTFILEP(id), 0L, SEEK_CUR) < 0)
                 {
                     return errno;
                 }

                /*
                 * Found the end of the file (marked by a 0 length buffer)
                 * Make sure we zero any trailing data.
                 */
                zero_point = ftell(KTFILEP(id));
                setbuf(KTFILEP(id), iobuf);
                while ((size = xfread(iobuf, 1, sizeof(iobuf), KTFILEP(id)))) {
                    if (size != sizeof(iobuf)) {
                        remainder = size % sizeof(krb5_int32);
                        if (remainder) {
                            size += sizeof(krb5_int32) - remainder;
                        }
                    }

                    if (fseek(KTFILEP(id), 0L, SEEK_CUR) < 0)
                    {
                        return errno;
                    }

                    memset(iobuf, 0, (size_t) size);
                    xfwrite(iobuf, 1, (size_t) size, KTFILEP(id));
                    if (feof(KTFILEP(id))) {
                        break;
                    }

                    if (fseek(KTFILEP(id), 0L, SEEK_CUR) < 0)
                    {
                        return errno;
                    }

                }
                setbuf(KTFILEP(id), 0);
                if (fseek(KTFILEP(id), zero_point, SEEK_SET)) {
                    return errno;
                }
            }
        }
    }

    return 0;
}

