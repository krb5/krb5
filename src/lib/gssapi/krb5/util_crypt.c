/*
 * Copyright 1993 by OpenVision Technologies, Inc.
 * 
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of OpenVision not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission. OpenVision makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 * 
 * OPENVISION DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL OPENVISION BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#include "k5-int.h"
#include "gssapiP_krb5.h"
#include <memory.h>

/*
 * $Id$
 */

static unsigned char zeros[8] = {0,0,0,0,0,0,0,0};

int
kg_confounder_size(ed)
     krb5_gss_enc_desc *ed;
{
   /* XXX Abstraction violation!!! */

   return(ed->eblock.crypto_entry->block_length);
}

krb5_error_code
kg_make_confounder(ed, buf)
     krb5_gss_enc_desc *ed;
     unsigned char *buf;
{
   /* XXX Abstraction violation!!! */

   return(krb5_random_confounder(ed->eblock.crypto_entry->block_length, buf));
}

int
kg_encrypt_size(ed, n)
     krb5_gss_enc_desc *ed;
     int n;
{
   return(krb5_encrypt_size(n, ed->eblock.crypto_entry));
}

krb5_error_code
kg_encrypt(context, ed, iv, in, out, length)
     krb5_context context;
     krb5_gss_enc_desc *ed;
     krb5_pointer iv;
     krb5_pointer in;
     krb5_pointer out;
     int length;
{
   krb5_error_code code;
   krb5_pointer tmp;

   if (! ed->processed) {
      if (code = krb5_process_key(context, &ed->eblock, ed->key))
	 return(code);
      ed->processed = 1;
   }

   /* this is lame.  the krb5 encryption interfaces no longer allow
      you to encrypt in place.  perhaps this should be fixed, but
      dealing here is easier for now --marc */

   if ((tmp = (krb5_pointer) xmalloc(length)) == NULL)
      return(ENOMEM);

   memcpy(tmp, in, length);

   code = krb5_encrypt(context, tmp, out, length, &ed->eblock, 
		       iv?iv:(krb5_pointer)zeros);

   xfree(tmp);

   if (code)
      return(code);

   return(0);
}

/* length is the length of the cleartext. */

krb5_error_code
kg_decrypt(context, ed, iv, in, out, length)
     krb5_context context;
     krb5_gss_enc_desc *ed;
     krb5_pointer iv;
     krb5_pointer in;
     krb5_pointer out;
     int length;
{
   krb5_error_code code;
   int elen;
   char *buf;

   if (! ed->processed) {
      if (code = krb5_process_key(context, &ed->eblock, ed->key))
	 return(code);
      ed->processed = 1;
   }

   elen = krb5_encrypt_size(length, ed->eblock.crypto_entry);
   if ((buf = (char *) xmalloc(elen)) == NULL)
      return(ENOMEM);

   if (code = krb5_decrypt(context, in, buf, elen, &ed->eblock, 
			   iv?iv:(krb5_pointer)zeros)) {
      xfree(buf);
      return(code);
   }

   memcpy(out, buf, length);
   xfree(buf);

   return(0);
}
