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
 * functions to validate name, credential, and context handles
 */

#include "gssapiP_generic.h"

#include <sys/types.h>
#include <sys/file.h>
#include <fcntl.h>
#include <limits.h>
#include <db.h>

#define V_NAME		1
#define V_CRED_ID	2
#define V_CTX_ID	3

typedef struct _vkey {
   int type;
   void *ptr;
} vkey;

static const int one = 1;
static const DBT dbtone = { (void *) &one, sizeof(one) };

/* All these functions return 0 on failure, and non-zero on success */

static int g_save(DB **vdb, int type, void *ptr)
{
   vkey vk;
   DBT key;

   if (!*vdb)
      *vdb = dbopen(NULL, O_CREAT|O_RDWR, O_CREAT|O_RDWR, DB_HASH, NULL);

   vk.type = type;
   vk.ptr = ptr;

   key.data = &vk;
   key.size = sizeof(vk);

   return((*((*vdb)->put))(*vdb, &key, &dbtone, 0) == 0);
}

static int g_validate(DB **vdb, int type, void *ptr)
{
   vkey vk;
   DBT key, value;

   if (!*vdb)
      return(0);

   vk.type = type;
   vk.ptr = ptr;

   key.data = &vk;
   key.size = sizeof(vk);

   if ((*((*vdb)->get))(*vdb, &key, &value, 0))
      return(0);

   return((value.size == sizeof(one)) &&
	  (*((int *) value.data) == one));
}

static int g_delete(DB **vdb, int type, void *ptr)
{
   vkey vk;
   DBT key;

   if (!*vdb)
      return(0);

   vk.type = type;
   vk.ptr = ptr;

   key.data = &vk;
   key.size = sizeof(vk);

   return((*((*vdb)->del))(*vdb, &key, 0) == 0);
}

/* functions for each type */

/* save */

int g_save_name(void **vdb, gss_name_t *name)
{
   return(g_save((DB **) vdb, V_NAME, (void *) name));
}
int g_save_cred_id(void **vdb, gss_cred_id_t *cred)
{
   return(g_save((DB **) vdb, V_CRED_ID, (void *) cred));
}
int g_save_ctx_id(void **vdb, gss_ctx_id_t *ctx)
{
   return(g_save((DB **) vdb, V_CTX_ID, (void *) ctx));
}

/* validate */

int g_validate_name(void **vdb, gss_name_t *name)
{
   return(g_validate((DB **) vdb, V_NAME, (void *) name));
}
int g_validate_cred_id(void **vdb, gss_cred_id_t *cred)
{
   return(g_validate((DB **) vdb, V_CRED_ID, (void *) cred));
}
int g_validate_ctx_id(void **vdb, gss_ctx_id_t *ctx)
{
   return(g_validate((DB **) vdb, V_CTX_ID, (void *) ctx));
}

/* delete */

int g_delete_name(void **vdb, gss_name_t *name)
{
   return(g_delete((DB **) vdb, V_NAME, (void *) name));
}
int g_delete_cred_id(void **vdb, gss_cred_id_t *cred)
{
   return(g_delete((DB **) vdb, V_CRED_ID, (void *) cred));
}
int g_delete_ctx_id(void **vdb, gss_ctx_id_t *ctx)
{
   return(g_delete((DB **) vdb, V_CTX_ID, (void *) ctx));
}

