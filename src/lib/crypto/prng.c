/*
 * Copyright (C) 2001, 2002 by the Massachusetts Institute of Technology.
 * All rights reserved.
 *
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
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

#include "k5-int.h"
#include "enc_provider.h"
#include <assert.h>

#include "yarrow.h"
static Yarrow_CTX y_ctx;
static int inited=0;

/* Helper function to estimate entropy based on sample length
 * and where it comes from.
 */

static size_t
entropy_estimate (unsigned int randsource, size_t length)
{
  switch (randsource) {
  case KRB5_C_RANDSOURCE_OLDAPI:
    return (4*length);
  case KRB5_C_RANDSOURCE_OSRAND:
    return (8*length);
  case KRB5_C_RANDSOURCE_TRUSTEDPARTY:
    return (4*length);
  case KRB5_C_RANDSOURCE_TIMING:return (2);
  case KRB5_C_RANDSOURCE_EXTERNAL_PROTOCOL:
    return (0);
  default:
    abort();
  }
return (0);
}

krb5_error_code KRB5_CALLCONV
krb5_c_random_add_entropy (krb5_context context, unsigned int randsource,
			   const krb5_data *data)
{
  int yerr;

  if (inited == 0) {
    unsigned i;
    yerr = krb5int_yarrow_init (&y_ctx, NULL);
    if ((yerr != YARROW_OK) && (yerr != YARROW_NOT_SEEDED))
      return (KRB5_CRYPTO_INTERNAL);
      

    for (i=0; i < KRB5_C_RANDSOURCE_MAX; i++ ) {
      unsigned  source_id;
      if (krb5int_yarrow_new_source (&y_ctx, &source_id) != YARROW_OK )
	return KRB5_CRYPTO_INTERNAL;
      assert (source_id == i);
    }
    inited=1;
      
  }
  yerr = krb5int_yarrow_input (&y_ctx, randsource,
			       data->data, data->length,
			       entropy_estimate (randsource, data->length));
  if (yerr != YARROW_OK)
    return (KRB5_CRYPTO_INTERNAL);
  return (0);
}

krb5_error_code KRB5_CALLCONV
krb5_c_random_seed
(krb5_context context, krb5_data *data)
{
  return (krb5_c_random_add_entropy (context,  KRB5_C_RANDSOURCE_OLDAPI, data));
}



krb5_error_code KRB5_CALLCONV
krb5_c_random_make_octets(krb5_context context, krb5_data *data)
{
    int yerr;
    assert (inited);
    yerr = krb5int_yarrow_output (&y_ctx, data->data, data->length);
    if (yerr == YARROW_NOT_SEEDED) {
      yerr = krb5int_yarrow_reseed (&y_ctx, YARROW_SLOW_POOL);
      if (yerr == YARROW_OK)
	yerr = krb5int_yarrow_output (&y_ctx, data->data, data->length);
    }
    if ( yerr != YARROW_OK)
      return (KRB5_CRYPTO_INTERNAL);
    return(0);
}

void prng_cleanup (void)
{
  if (inited) krb5int_yarrow_final (&y_ctx);
	inited = 0;
}


/*
 * Routines to get entropy from the OS.  For UNIX we try /dev/urandom
 * and /dev/random.  Currently we don't do anything for Windows.
 */
#if defined(_WIN32)

krb5_error_code KRB5_CALLCONV
krb5_c_random_os_entropy (
			  krb5_context context, int strong, int *success)
{
  if (success)
    *success  = 0;
  return 0;
}

#else /*Windows*/
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

/*
 * Helper function to read entropy from  a random device.  Takes the
 * name of a device, opens it, makes sure it is a device and if so,
 * reads entropy.  Returns  a boolean indicating whether entropy was
 * read.
 */

static int
read_entropy_from_device (krb5_context context, const char *device)
{
  krb5_data data;
  struct stat sb;
  int fd;
  unsigned char buf[YARROW_SLOW_THRESH/8];
  int left;
  fd = open (device, O_RDONLY);
  if (fd == -1)
    return 0;
  if (fstat (fd, &sb) == -1)
    return 0;
  if (S_ISREG(sb.st_mode)) {
    close(fd);
    return 0;
  }
  for (left = sizeof (buf); left > 0;) {
    size_t count;
    count = read (fd, &buf, (unsigned) left);
    if (count <= 0) {
      close(fd);
      return 0;
    }
    left -= count;
  }
  close (fd);
  data.length = sizeof (buf);
  data.data = ( char * ) buf;
  if ( krb5_c_random_add_entropy (context, KRB5_C_RANDSOURCE_OSRAND, 
				  &data) != 0) {
    return 0;
  }
  return 1;
}
    
krb5_error_code KRB5_CALLCONV
krb5_c_random_os_entropy (krb5_context context,
			  int strong, int *success)
{
  int unused;
  int *oursuccess = success?success:&unused;
  *oursuccess = 0;
  /* If we are getting strong data then try that first.  We aare
     guaranteed to cause a reseed of some kind if strong is true and
     we have both /dev/random and /dev/urandom.  We want the strong
     data included in the reseed so we get it first.*/
  if (strong) {
    if (read_entropy_from_device (context, "/dev/random"))
      *oursuccess = 1;
  }
  if (read_entropy_from_device (context, "/dev/urandom"))
    *oursuccess = 1;
  return 0;
}

#endif /*Windows or pre-OSX Mac*/
