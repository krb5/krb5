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

#ifndef _GSSAPIP_GENERIC_H_
#define _GSSAPIP_GENERIC_H_

/*
 * $Id$
 */

#include "gssapi.h"

#include "gssapi_generic_err.h"
#include <errno.h>

/** helper macros **/

#define g_OID_equal(o1,o2) \
   (((o1)->length == (o2)->length) && \
    (memcmp((o1)->elements,(o2)->elements,(o1)->length) == 0))

#define TWRITE_INT(ptr, tmp, num) \
   (tmp) = htonl(num); \
   memcpy(ptr, (char *) &(tmp), sizeof(tmp)); \
   (ptr) += sizeof(tmp);
	     
#define TREAD_INT(ptr, num) \
   memcpy((char *) &(num), (char *) (ptr), sizeof(num)); \
   (num) = ntohl(num); \
   (ptr) += sizeof(num);

#define TWRITE_STR(ptr, str, len) \
   memcpy((ptr), (char *) (str), (len)); \
   (ptr) += (len);

#define TREAD_STR(ptr, str, len) \
   (str) = (ptr); \
   (ptr) += (len);

#define TWRITE_BUF(ptr, tmp, buf) \
   TWRITE_INT((ptr), (tmp), (buf).length); \
   TWRITE_STR((ptr), (buf).value, (buf).length);

/** malloc wrappers; these may actually do something later */

#define xmalloc(n) malloc(n)
#define xrealloc(p,n) realloc(p,n)
#ifdef xfree
#undef xfree
#endif
#define xfree(p) free(p)

/** helper functions **/

int g_save_name(void **vdb, gss_name_t *name);
int g_save_cred_id(void **vdb, gss_cred_id_t *cred);
int g_save_ctx_id(void **vdb, gss_ctx_id_t *ctx);

int g_validate_name(void **vdb, gss_name_t *name);
int g_validate_cred_id(void **vdb, gss_cred_id_t *cred);
int g_validate_ctx_id(void **vdb, gss_ctx_id_t *ctx);

int g_delete_name(void **vdb, gss_name_t *name);
int g_delete_cred_id(void **vdb, gss_cred_id_t *cred);
int g_delete_ctx_id(void **vdb, gss_ctx_id_t *ctx);

int g_make_string_buffer(const char *str, gss_buffer_t buffer);

int g_copy_OID_set(const gss_OID_set_desc * const in, gss_OID_set *out);

int g_token_size(const_gss_OID mech, unsigned int body_size);

void g_make_token_header(const_gss_OID mech, int body_size,
			  unsigned char **buf, int tok_type);

int g_verify_token_header(const_gss_OID mech, int *body_size,
			  unsigned char **buf, int tok_type, int toksize);

OM_uint32 g_display_major_status(OM_uint32 *minor_status,
				 OM_uint32 status_value,
				 int *message_context,
				 gss_buffer_t status_string);

OM_uint32 g_display_com_err_status(OM_uint32 *minor_status,
				   OM_uint32 status_value,
				   gss_buffer_t status_string);

char *g_canonicalize_host(char *hostname);

char *g_strdup(char *str);

/** declarations of internal name mechanism functions **/

OM_uint32 generic_gss_release_buffer
           (OM_uint32*,       /* minor_status */
            gss_buffer_t      /* buffer */
           );

OM_uint32 generic_gss_release_oid_set
           (OM_uint32*,       /* minor_status */
            gss_OID_set*      /* set */
           );

#endif /* _GSSAPIP_GENERIC_H_ */
