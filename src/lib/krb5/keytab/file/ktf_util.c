/*
 * $Source$
 * $Author$
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America is assumed
 *   to require a specific license from the United States Government.
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
#include <krb5/los-proto.h>

#include "ktfile.h"
#include <krb5/osconf.h>

/* keytab version 1 didn't do byte swapping correctly; call this version 2
   so old files will be recognized as old instead of badly formatted. */
#define KRB5_KT_VNO	0x0502		/* krb5, keytab v 2 */

extern int errno;

static krb5_error_code
krb5_ktfileint_open(id, mode)
krb5_keytab id;
int mode;
{
    register FILE *fp;
    krb5_error_code kerror;
    int writevno = 0;
#ifdef POSIX_TYPES
    mode_t omask;
#else
    int omask;
#endif

    /* Make sure nobody else can read the new file.  It might be better
       to use open with mode 600 followed by fdopen on UNIX systems.  */
    omask = umask(066);

#ifdef ANSI_STDIO
    fp = fopen(KTFILENAME(id),
	       (mode == KRB5_LOCKMODE_EXCLUSIVE) ? "rb+" : "rb");
#else
    fp = fopen(KTFILENAME(id),
	       (mode == KRB5_LOCKMODE_EXCLUSIVE) ? "r+" : "r");
#endif
    if (!fp) {
	if ((mode == KRB5_LOCKMODE_EXCLUSIVE) && (errno == ENOENT)) {
	    /* try making it first time around */
#ifdef ANSI_STDIO
	    fp = fopen(KTFILENAME(id), "ab+");
#else
	    fp = fopen(KTFILENAME(id), "a+");
#endif
	    if (!fp) {
		(void) umask (omask);
		return errno;
	    }
	    writevno = 1;
	} else {			/* some other error */
	    (void) umask (omask);
	    return errno;
	}
    }
    (void) umask (omask);

    if (kerror = krb5_lock_file(fp, KTFILENAME(id), mode)) {
	(void) fclose(fp);
	return kerror;
    }

    /* get the vno and verify it */
    if (writevno) {
	/* Write a version number, MSB first. */
	if (putc((KRB5_KT_VNO >> 8), fp) == EOF || putc(KRB5_KT_VNO, fp) == EOF) {
	    (void) krb5_unlock_file(fp, KTFILENAME(id));
	    (void) fclose(fp);
	    return KRB5_KT_IOERR;
	}
    } else {
	int c1, c2;

	/* Verify version number. */
	c1 = getc(fp);
	c2 = getc(fp);

	if (c1 == EOF || c2 == EOF) {
	    kerror = feof(fp) ? KRB5_KT_END : KRB5_KT_IOERR;
	    (void) krb5_unlock_file(fp, KTFILENAME(id));
	    (void) fclose(fp);
	    return kerror;
	}
	if ((c1 << 8) + c2 != KRB5_KT_VNO) {
	    (void) krb5_unlock_file(fp, KTFILENAME(id));
	    (void) fclose(fp);
	    return KRB5_KEYTAB_BADVNO;
	}
    }
    /* seek to the end for writers */
    if (mode == KRB5_LOCKMODE_EXCLUSIVE) {
	if (fseek(fp, 0, 2)) {
	    (void) krb5_unlock_file(fp, KTFILENAME(id));
	    (void) fclose(fp);
	    return KRB5_KT_IOERR;
	}
    }
    KTFILEP(id) = fp;
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
	return 0;
    kerror = krb5_unlock_file(KTFILEP(id), KTFILENAME(id));
    (void) fclose(KTFILEP(id));
    KTFILEP(id) = 0;
    return kerror;
}

/* Keytab file format.  This is not documented anywhere and is not known
   outside this file.

   Each entry in the file contains:

   prinicipal name:
     2 byte count of number of components in name
        component:
	  2 byte count of number of bytes
	  data
   1 byte key version number
   2 byte key type
   4 byte key length
   key data

   The write file function could do range checking on 2 byte quantities,
   but doesn't.  Values greater than 2 ^ 15 are unlikely.
*/

krb5_error_code
krb5_ktfileint_read_entry(id, entryp)
krb5_keytab id;
krb5_keytab_entry **entryp;
{
  krb5_keytab_entry *entry;
  register FILE *fp = KTFILEP(id);
  int i;	/* index into principal component array; failure cleanup
		   code uses this to determine how much to free */
  int count;
  int size;
  int c1, c2;
  krb5_error_code error;

  entry = (krb5_keytab_entry *)malloc (sizeof (krb5_keytab_entry));
  if (entry == 0)
    return ENOMEM;

  /* Read a character at a time to avoid any problems with byte order. */
  c1 = getc(fp);
  c2 = getc(fp);
  if (c1 == EOF || c2 == EOF)
    return KRB5_KT_END;

  count = (c1 << 8) + c2;

  if (!(entry->principal = (krb5_principal)malloc(sizeof(krb5_principal_data))))
    return ENOMEM;
  if (!(entry->principal->data = (krb5_data *)malloc(count * sizeof(krb5_data))))
    {
      free((char *)entry->principal);
      return ENOMEM;
    }
  entry->principal->length = count;

  {
    char *tmpdata;

    c1 = getc(fp);
    c2 = getc(fp);
    if (c1 == EOF || c2 == EOF)
      {
	error = KRB5_KT_END;
	goto fail;
      }
      size = (c1 << 8) + c2;
    krb5_princ_set_realm_length(entry->principal, size);
    if ((tmpdata = malloc (size)) == 0)
	{
	  error = ENOMEM;
	  goto fail;
	}
    if (fread(tmpdata, 1, size, fp) != size)
      {
	free (tmpdata);
	error = KRB5_KT_END;
	goto fail;
      }
    krb5_princ_set_realm_data(entry->principal, tmpdata);
  }

  for (i = 0; i < count; i++)
    {
      krb5_data *princ = krb5_princ_component(entry->principal, i);

      c1 = getc(fp);
      c2 = getc(fp);
      if (c1 == EOF || c2 == EOF)
	{
	  error = KRB5_KT_END;
	  goto fail;
	}

      size = (c1 << 8) + c2;

      princ->length = size;
      if ((princ->data = malloc (size)) == 0)
	{
	  error = ENOMEM;
	  goto fail;
	}
      if (fread(princ->data, 1, size, fp) != size)
	{
	  free (princ->data);
	  error = KRB5_KT_END;
	  goto fail;
	}
    }

  /* key version number: 1 byte */
  c1 = getc(fp);
  if (c1 == EOF)
    {
      error = KRB5_KT_END;
      goto fail;
    }
  entry->vno = c1;
  /* keyblock: keytype (2), length (4), contents */
  c1 = getc(fp);
  c2 = getc(fp);
  if (c1 == EOF || c2 == EOF)
    {
      error = KRB5_KT_END;
      goto fail;
    }
  entry->key.keytype = (c1 << 8) | c2;
  c1 = getc(fp);
  c2 = getc(fp);
  if (c1 == EOF || c2 == EOF)
    {
      error = KRB5_KT_END;
      goto fail;
    }
  size = (c1 << 24) + (c2 << 16);
  c1 = getc(fp);
  c2 = getc(fp);
  if (c1 == EOF || c2 == EOF)
    {
      error = KRB5_KT_END;
      goto fail;
    }
  size += (c1 << 8) + c2;

  entry->key.length = size;
  if ((entry->key.contents = (krb5_octet *)malloc(size)) == 0)
    {
      error = ENOMEM;
      goto fail;
    }

  if (fread((char *)entry->key.contents, 1, size, fp) != size)
    {
      free(entry->key.contents);
      error = KRB5_KT_END;
      goto fail;
    }
  *entryp = entry;
  return 0;

 fail:
  free((char *)entry->principal->data);
  free((char *)entry->principal);
  return error;
}

krb5_error_code
krb5_ktfileint_write_entry(id, entry)
krb5_keytab id;
register krb5_keytab_entry *entry;
{
  register FILE *fp = KTFILEP(id);
  int count, size;
  unsigned char c1, c2;
  register int i;

  /* Do all I/O and check for error once at the end.  This function isn't
     expensive, and errors should be rare. */

  count = krb5_princ_size(entry->principal);

  /* 2 byte count of number of components in name, MSB first. */

  c2 = count;
  c1 = count >> 8;

  putc(c1, fp);
  putc(c2, fp);

    {
      size = krb5_princ_realm(entry->principal)->length;

      c2 = size;
      c1 = size >> 8;

      putc(c1, fp);
      putc(c2, fp);

      fwrite(krb5_princ_realm(entry->principal)->data, 1, size, fp);
    }

  for (i = 0; i < count; i++)
    {
      size = krb5_princ_component(entry->principal, i)->length;

      c2 = size;
      c1 = size >> 8;

      putc(c1, fp);
      putc(c2, fp);

      fwrite(krb5_princ_component(entry->principal, i)->data, 1, size, fp);
    }
  /* Version number is one byte. */
  putc(entry->vno, fp);

  /* Key type is 2 bytes. */
  c2 = entry->key.keytype;
  c1 = entry->key.keytype >> 8;

  putc(c1, fp);
  putc(c2, fp);

  size = entry->key.length;

  c1 = size >> 24;
  c2 = size >> 16;
  putc(c1, fp);
  putc(c2, fp);
  c1 = size >> 8;
  c2 = size;
  putc(c1, fp);
  putc(c2, fp);

  fwrite((char *)entry->key.contents, 1, size, fp);

  if (fflush(fp) == EOF || ferror(fp))
    return KRB5_KT_IOERR;
  return 0;
}
