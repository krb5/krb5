/*
 * $Source$
 * $Author$
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
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
 * principal vno key
 * principal vno key
 * ....
 *
 * There are no separators between fields of an entry or between entries.
 * A principal is a length-encoded array of length-encoded strings.  The
 * length is a krb5_int16 in each case.  The specific format, then, is 
 * multiple entries concatinated with no separators.  An entry has this 
 * exact format:
 *
 * sizeof(krb5_int16) bytes for number of components in the principal; 
 * then, each component listed in ordser.
 * For each component, sizeof(krb5_int16) bytes for the number of bytes
 * in the component, followed by the component.
 * sizeof(krb5_kvno) bytes for the key version number
 * sizeof(krb5_keytype) bytes for the keytype
 * sizeof(krb5_int32) bytes for the key length, followed by the key
 *
 * Extra garbage at the end of a keytab will be not be searched for, but
 * 
 * 
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_ktf_util_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>
#include <krb5/libos.h>
#include <krb5/libos-proto.h>

#include "ktfile.h"
#include <netinet/in.h>			/* XXX ip only? */

#define KRB5_KT_VNO	0x0501		/* krb5, keytab v 1 */

#define xfwrite(a, b, c, d) fwrite((char *)a, b, c, d)
#define xfread(a, b, c, d) fread((char *)a, b, c, d)

extern int errno;

static krb5_error_code
krb5_ktfileint_open(id, mode)
krb5_keytab id;
int mode;
{
    krb5_error_code kerror;
    krb5_int16 kt_vno = htons(KRB5_KT_VNO);
    int writevno = 0;

/* XXX temp hack on vax */
#if defined(__STDC__) && !defined(vax)
    KTFILEP(id) = fopen(KTFILENAME(id),
			(mode == KRB5_LOCKMODE_EXCLUSIVE) ? "rb+" : "rb");
#else
    KTFILEP(id) = fopen(KTFILENAME(id),
			(mode == KRB5_LOCKMODE_EXCLUSIVE) ? "r+" : "r");
#endif
    if (!KTFILEP(id)) {
	if ((mode == KRB5_LOCKMODE_EXCLUSIVE) && (errno == ENOENT)) {
	    /* try making it first time around */
	    KTFILEP(id) = fopen(KTFILENAME(id), "a+");
	    if (!KTFILEP(id))
		return errno;
	    writevno = 1;
	} else				/* some other error */
	    return errno;
    }
    if (kerror = krb5_lock_file(KTFILEP(id), KTFILENAME(id),
				mode)) {
	(void) fclose(KTFILEP(id));
	KTFILEP(id) = 0;
	return kerror;
    }
    /* assume ANSI or BSD-style stdio */
    setbuf(KTFILEP(id), NULL);

    /* get the vno and verify it */
    if (writevno) {
	if (!xfwrite(&kt_vno, sizeof(kt_vno), 1, KTFILEP(id))) {
	    kerror = errno;
	    (void) krb5_unlock_file(KTFILEP(id), KTFILENAME(id));
	    (void) fclose(KTFILEP(id));
	    return kerror;
	}
    } else {
	/* gotta verify it instead... */
	if (!xfread(&kt_vno, sizeof(kt_vno), 1, KTFILEP(id))) {
	    kerror = errno;
	    (void) krb5_unlock_file(KTFILEP(id), KTFILENAME(id));
	    (void) fclose(KTFILEP(id));
	    return kerror;
	}
	if (kt_vno != ntohs(KRB5_KT_VNO)) {
	    (void) krb5_unlock_file(KTFILEP(id), KTFILENAME(id));
	    (void) fclose(KTFILEP(id));
	    return KRB5_KEYTAB_BADVNO;
	}
    }
    /* seek to the end for writers */
    if (mode == KRB5_LOCKMODE_EXCLUSIVE) {
	if (fseek(KTFILEP(id), 0, 2)) {
	    kerror = errno;
	    (void) krb5_unlock_file(KTFILEP(id), KTFILENAME(id));
	    (void) fclose(KTFILEP(id));
	    return kerror;
	}
    }
    return 0;
}

krb5_error_code
krb5_ktfileint_openr(id)
krb5_keytab id;
{
    return krb5_ktfileint_open(id, KRB5_LOCKMODE_SHARED);
}

krb5_error_code
krb5_ktfileint_openw(id)
krb5_keytab id;
{
    return krb5_ktfileint_open(id, KRB5_LOCKMODE_EXCLUSIVE);
}

krb5_error_code
krb5_ktfileint_close(id)
krb5_keytab id;
{
    krb5_error_code kerror;

    if (!KTFILEP(id))
	return 0;			/* XXX? ordering */
    kerror = krb5_unlock_file(KTFILEP(id), KTFILENAME(id));
    (void) fclose(KTFILEP(id));
    KTFILEP(id) = 0;
    return kerror;
}

krb5_error_code
krb5_ktfileint_read_entry(id, entrypp)
krb5_keytab id;
krb5_keytab_entry **entrypp;
{
    register krb5_keytab_entry *ret_entry;
    krb5_int16 count;
    krb5_int16 princ_size;
    register int i;

    if (!(ret_entry = (krb5_keytab_entry *)calloc(1, sizeof(*ret_entry))))
	return ENOMEM;


    /* deal with guts of parsing... */

    /* first, int16 with #princ components */
    if (!xfread(&count, sizeof(count), 1, KTFILEP(id)))
	return KRB5_KT_END;
    if (!count || (count < 0))
	return KRB5_KT_END;		/* XXX */
    if (!(ret_entry->principal = (krb5_data **)calloc(count+1, sizeof(krb5_data *))))
	return ENOMEM;
    for (i = 0; i < count; i++) {
	if (!xfread(&princ_size, sizeof(princ_size), 1, KTFILEP(id)))
	    return KRB5_KT_END;
	if (!princ_size || (princ_size < 0))
	    return KRB5_KT_END;		/* XXX */

	if (!(ret_entry->principal[i] = (krb5_data *)malloc(sizeof(krb5_data))))
	    return ENOMEM;
	ret_entry->principal[i]->length = princ_size;
	ret_entry->principal[i]->data = malloc(princ_size);
	if (!ret_entry->principal[i]->data)
	    return ENOMEM;
	if (!xfread(ret_entry->principal[i]->data, sizeof(char), princ_size,
		    KTFILEP(id)))
	    return KRB5_KT_END;
    }
    if (!xfread(&ret_entry->vno, sizeof(ret_entry->vno), 1, KTFILEP(id)))
	return KRB5_KT_END;
    /* key type */
    if (!xfread(&ret_entry->key.keytype, sizeof(ret_entry->key.keytype), 1,
		KTFILEP(id)))
	return KRB5_KT_END;
    /* key contents */
    if (!xfread(&count, sizeof(count), 1, KTFILEP(id)))
	return KRB5_KT_END;
    if (!count || (count < 0))
	return KRB5_KT_END;		/* XXX */
    ret_entry->key.length = count;
    if (!(ret_entry->key.contents = (krb5_octet *)malloc(count)))
	return ENOMEM;
    if (!xfread(ret_entry->key.contents, sizeof(krb5_octet), count,
		KTFILEP(id)))
	return KRB5_KT_END;

    *entrypp = ret_entry;
    return 0;
}

krb5_error_code
krb5_ktfileint_write_entry(id, entry)
krb5_keytab id;
krb5_keytab_entry *entry;
{
    krb5_data **princp;
    krb5_int16 count, size;
    krb5_error_code retval = 0;
    char iobuf[BUFSIZ];

    setbuf(KTFILEP(id), iobuf);

    /* count up principal components */
    for (count = 0, princp = entry->principal; *princp; princp++, count++);

    if (!xfwrite(&count, sizeof(count), 1, KTFILEP(id))) {
    abend:
	setbuf(KTFILEP(id), 0);
	return KRB5_KT_IOERR;
    }

    for (princp = entry->principal; *princp; princp++) {
	size = (*princp)->length;
	if (!xfwrite(&size, sizeof(size), 1, KTFILEP(id))) {
	    goto abend;
	}
	if (!xfwrite((*princp)->data, sizeof(char), size, KTFILEP(id))) {
	    goto abend;
	}
    }
    if (!xfwrite(&entry->vno, sizeof(entry->vno), 1, KTFILEP(id))) {
	goto abend;
    }
    if (!xfwrite(&entry->key.keytype, sizeof(entry->key.keytype), 1,
		 KTFILEP(id))) {
	goto abend;
    }
    size = entry->key.length;
    if (!xfwrite(&size, sizeof(size), 1, KTFILEP(id))) {
	goto abend;
    }
    if (!xfwrite(entry->key.contents, sizeof(krb5_octet), size, KTFILEP(id))) {
	memset(iobuf, 0, sizeof(iobuf));
	setbuf(KTFILEP(id), 0);
	return KRB5_KT_IOERR;
    }	
    if (fflush(KTFILEP(id)) == EOF)
	retval = errno;

    (void) memset(iobuf, 0, sizeof(iobuf));
    setbuf(KTFILEP(id), 0);
    return retval;
}
