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
 * $Id$
 */

/* This file could be OS specific */

#include "gssapiP_generic.h"

#include "port-sockets.h"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#include <ctype.h>
#include <string.h>

char *
g_canonicalize_host(hostname)
     char *hostname;
{
   struct hostent *hent;
   char *haddr;
   char *canon, *str;

   if ((hent = gethostbyname(hostname)) == NULL)
      return(NULL);

   if (! (haddr = (char *) xmalloc(hent->h_length))) {
	return(NULL);
   }

   memcpy(haddr, hent->h_addr_list[0], hent->h_length);

   if (! (hent = gethostbyaddr(haddr, hent->h_length, hent->h_addrtype))) {
	return(NULL);
   }

   xfree(haddr);

   if ((canon = (char *) xmalloc(strlen(hent->h_name)+1)) == NULL)
      return(NULL);

   strcpy(canon, hent->h_name);

   for (str = canon; *str; str++)
      if (isupper(*str)) *str = tolower(*str);

   return(canon);
}
