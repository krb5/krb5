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

#include "gssapiP_generic.h"

/*
 * $Id$
 */

int
g_copy_OID_set(in, out)
     const gss_OID_set_desc * const in;
     gss_OID_set *out;
{
   gss_OID_set copy;
   gss_OID     new_oid;
   size_t      i;
   size_t      len;

   *out = NULL;

   if ((copy =
	(gss_OID_set_desc *) xmalloc(sizeof(gss_OID_set_desc))) == NULL)
      return(0);

   copy->count = in->count;
   len = sizeof(gss_OID_desc) * copy->count;

   if ((copy->elements = 
	(gss_OID_desc *) xmalloc( len )) == NULL) {
      xfree(copy);
      return(0);
   }

   memset( copy->elements, 0, len );
   
   for (i=0; i<in->count; i++) {
      len = in->elements[i].length;
      new_oid = &(copy->elements[i]);
      new_oid->elements = xmalloc( len );
      if ( new_oid->elements == NULL ) {
         while( i>0 ) {
            i--;
            new_oid = &(copy->elements[i]);
            if ( new_oid->elements!=NULL )
               xfree( new_oid->elements );
         }
         xfree( copy->elements );
         xfree( copy );
         return( 0 );
      }
      memcpy( new_oid->elements, in->elements[i].elements, len );
      new_oid->length = len;
   }

   *out = copy;
   return(1);
}
