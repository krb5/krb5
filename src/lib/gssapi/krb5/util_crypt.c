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

#include "k5-int.h"
#include "gssapiP_krb5.h"
#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif

/*
 * $Id$
 */

static unsigned char zeros[8] = {0,0,0,0,0,0,0,0};

int
kg_confounder_size(context, key)
     krb5_context context;
     krb5_keyblock *key;
{
   krb5_error_code code;
   size_t blocksize;

   if (code = krb5_c_block_size(context, key->enctype, &blocksize))
      return(-1); /* XXX */

   return(blocksize);
}

krb5_error_code
kg_make_confounder(context, key, buf)
     krb5_context context;
     krb5_keyblock *key;
     unsigned char *buf;
{
   krb5_error_code code;
   size_t blocksize;
   krb5_data random;

   if (code = krb5_c_block_size(context, key->enctype, &blocksize))
       return(code);

   random.length = blocksize;
   random.data = buf;

   return(krb5_c_random_make_octets(context, &random));
}

int
kg_encrypt_size(context, key, n)
     krb5_context context;
     krb5_keyblock *key;
     int n;
{
   krb5_error_code code;
   size_t enclen;

   if (code = krb5_c_encrypt_length(context, key->enctype, n, &enclen))
      return(-1); /* XXX */

   return(enclen);
}

krb5_error_code
kg_encrypt(context, key, iv, in, out, length)
     krb5_context context;
     krb5_keyblock *key;
     krb5_pointer iv;
     krb5_pointer in;
     krb5_pointer out;
     int length;
{
   krb5_error_code code;
   size_t blocksize;
   krb5_data ivd, *pivd, inputd;
   krb5_enc_data outputd;

   if (iv) {
       if (code = krb5_c_block_size(context, key->enctype, &blocksize))
	   return(code);

       ivd.length = blocksize;
       ivd.data = iv;
       pivd = &ivd;
   } else {
       pivd = NULL;
   }

   inputd.length = length;
   inputd.data = in;

   outputd.ciphertext.length = length;
   outputd.ciphertext.data = out;

   return(krb5_c_encrypt(context, key,
			 /* XXX this routine is only used for the old
			    bare-des stuff which doesn't use the
			    key usage */ 0, pivd, &inputd, &outputd));
}

/* length is the length of the cleartext. */

krb5_error_code
kg_decrypt(context, key, iv, in, out, length)
     krb5_context context;
     krb5_keyblock *key;
     krb5_pointer iv;
     krb5_pointer in;
     krb5_pointer out;
     int length;
{
   krb5_error_code code;
   size_t blocksize, enclen;
   krb5_data ivd, *pivd, outputd;
   krb5_enc_data inputd;

   if (iv) {
       if (code = krb5_c_block_size(context, key->enctype, &blocksize))
	   return(code);

       ivd.length = blocksize;
       ivd.data = iv;
       pivd = &ivd;
   } else {
       pivd = NULL;
   }

   inputd.enctype = ENCTYPE_UNKNOWN;
   inputd.ciphertext.length = length;
   inputd.ciphertext.data = in;

   outputd.length = length;
   outputd.data = out;

   return(krb5_c_decrypt(context, key,
			 /* XXX this routine is only used for the old
			    bare-des stuff which doesn't use the
			    key usage */ 0, pivd, &inputd, &outputd));
}
