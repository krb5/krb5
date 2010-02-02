/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved
 *
 * $Header$
 */

#if !defined(lint) && !defined(__CODECENTER__)
static char *rcsid = "$Header$";
#endif

#include    <gssrpc/rpc.h>
#include    <kadm5/admin.h>
#include    <kadm5/kadm_rpc.h>
#ifdef HAVE_MEMORY_H
#include    <memory.h>
#endif
#include    <string.h>
#include    <errno.h>
#include    "client_internal.h"

#ifdef DEBUG
#define eret() do { clnt_perror(handle->clnt, "null ret"); return KADM5_RPC_ERROR; } while (0)
#else
#define eret() do { return KADM5_RPC_ERROR; } while (0)
#endif

kadm5_ret_t
kadm5_create_principal(void *server_handle,
			    kadm5_principal_ent_t princ, long mask,
			    char *pw)
{
    generic_ret		*r;
    cprinc_arg		arg;
    kadm5_server_handle_t handle = server_handle;

    CHECK_HANDLE(server_handle);

    memset(&arg, 0, sizeof(arg));
    arg.mask = mask;
    arg.passwd = pw;
    arg.api_version = handle->api_version;

    if(princ == NULL)
	return EINVAL;

    if (handle->api_version == KADM5_API_VERSION_1) {
       memcpy(&arg.rec, princ, sizeof(kadm5_principal_ent_rec_v1));
    } else {
       memcpy(&arg.rec, princ, sizeof(kadm5_principal_ent_rec));
    }
    if (handle->api_version == KADM5_API_VERSION_1) {
	 /*
	  * hack hack cough cough.
	  * krb5_unparse name dumps core if we pass it in garbage
	  * or null. So, since the client is not allowed to set mod_name
	  * anyway, we just fill it in with a dummy principal. The server of
	  * course ignores this.
	  */
	 krb5_parse_name(handle->context, "bogus/bogus", &arg.rec.mod_name);
    } else
	 arg.rec.mod_name = NULL;
    
    if(!(mask & KADM5_POLICY))
	arg.rec.policy = NULL;
    if (! (mask & KADM5_KEY_DATA)) {
	 arg.rec.n_key_data = 0;
	 arg.rec.key_data = NULL;
    }
    if (! (mask & KADM5_TL_DATA)) {
	 arg.rec.n_tl_data = 0;
	 arg.rec.tl_data = NULL;
    }
	 
    r = create_principal_2(&arg, handle->clnt);

    if (handle->api_version == KADM5_API_VERSION_1)
	 krb5_free_principal(handle->context, arg.rec.mod_name);

    if(r == NULL)
	eret();
    return r->code;
}

kadm5_ret_t
kadm5_create_principal_3(void *server_handle,
			 kadm5_principal_ent_t princ, long mask,
			 int n_ks_tuple,
			 krb5_key_salt_tuple *ks_tuple,
			 char *pw)
{
    generic_ret		*r;
    cprinc3_arg		arg;
    kadm5_server_handle_t handle = server_handle;

    CHECK_HANDLE(server_handle);

    memset(&arg, 0, sizeof(arg));
    arg.mask = mask;
    arg.passwd = pw;
    arg.api_version = handle->api_version;
    arg.n_ks_tuple = n_ks_tuple;
    arg.ks_tuple = ks_tuple;

    if(princ == NULL)
	return EINVAL;

    if (handle->api_version == KADM5_API_VERSION_1) {
       memcpy(&arg.rec, princ, sizeof(kadm5_principal_ent_rec_v1));
    } else {
       memcpy(&arg.rec, princ, sizeof(kadm5_principal_ent_rec));
    }
    if (handle->api_version == KADM5_API_VERSION_1) {
	 /*
	  * hack hack cough cough.
	  * krb5_unparse name dumps core if we pass it in garbage
	  * or null. So, since the client is not allowed to set mod_name
	  * anyway, we just fill it in with a dummy principal. The server of
	  * course ignores this.
	  */
	 krb5_parse_name(handle->context, "bogus/bogus", &arg.rec.mod_name);
    } else
	 arg.rec.mod_name = NULL;
    
    if(!(mask & KADM5_POLICY))
	arg.rec.policy = NULL;
    if (! (mask & KADM5_KEY_DATA)) {
	 arg.rec.n_key_data = 0;
	 arg.rec.key_data = NULL;
    }
    if (! (mask & KADM5_TL_DATA)) {
	 arg.rec.n_tl_data = 0;
	 arg.rec.tl_data = NULL;
    }
	 
    r = create_principal3_2(&arg, handle->clnt);

    if (handle->api_version == KADM5_API_VERSION_1)
	 krb5_free_principal(handle->context, arg.rec.mod_name);

    if(r == NULL)
	eret();
    return r->code;
}

kadm5_ret_t
kadm5_delete_principal(void *server_handle, krb5_principal principal)
{
    dprinc_arg		arg;
    generic_ret		*r;
    kadm5_server_handle_t handle = server_handle;

    CHECK_HANDLE(server_handle);

    if(principal == NULL)
	return EINVAL;
    arg.princ = principal;
    arg.api_version = handle->api_version;
    r = delete_principal_2(&arg, handle->clnt);
    if(r == NULL)
	eret();    
    return r->code;
}

kadm5_ret_t
kadm5_modify_principal(void *server_handle,
			    kadm5_principal_ent_t princ, long mask)
{
    mprinc_arg		arg;
    generic_ret		*r;
    kadm5_server_handle_t handle = server_handle;

    CHECK_HANDLE(server_handle);

    memset(&arg, 0, sizeof(arg));
    arg.mask = mask;
    arg.api_version = handle->api_version;
    /*
     * cough cough gag gag
     * see comment in create_principal.
     */
    if(princ == NULL)
	return EINVAL;
    if (handle->api_version == KADM5_API_VERSION_1) {
        memcpy(&arg.rec, princ, sizeof(kadm5_principal_ent_rec_v1));
    } else {
        memcpy(&arg.rec, princ, sizeof(kadm5_principal_ent_rec));
    }
    if(!(mask & KADM5_POLICY))
	arg.rec.policy = NULL;
    if (! (mask & KADM5_KEY_DATA)) {
	 arg.rec.n_key_data = 0;
	 arg.rec.key_data = NULL;
    }
    if (! (mask & KADM5_TL_DATA)) {
	 arg.rec.n_tl_data = 0;
	 arg.rec.tl_data = NULL;
    }

    if (handle->api_version == KADM5_API_VERSION_1) {
	 /*
	  * See comment in create_principal
	  */
	 krb5_parse_name(handle->context, "bogus/bogus", &arg.rec.mod_name);
    } else
	 arg.rec.mod_name = NULL;
    
    r = modify_principal_2(&arg, handle->clnt);

    if (handle->api_version == KADM5_API_VERSION_1)
	 krb5_free_principal(handle->context, arg.rec.mod_name);    

    if(r == NULL)
	eret();    
    return r->code;
}

kadm5_ret_t
kadm5_get_principal(void *server_handle,
		    krb5_principal princ, kadm5_principal_ent_t ent,
		    long mask)
{
    gprinc_arg	arg;
    gprinc_ret	*r;
    kadm5_server_handle_t handle = server_handle;

    CHECK_HANDLE(server_handle);

    if(princ == NULL)
	return EINVAL;
    arg.princ = princ;
    if (handle->api_version == KADM5_API_VERSION_1)
       arg.mask = KADM5_PRINCIPAL_NORMAL_MASK;
    else
       arg.mask = mask;
    arg.api_version = handle->api_version;
    r = get_principal_2(&arg, handle->clnt);
    if(r == NULL)
	eret();
    if (handle->api_version == KADM5_API_VERSION_1) {
	 kadm5_principal_ent_t_v1 *entp;

	 entp = (kadm5_principal_ent_t_v1 *) ent;
	 if (r->code == 0) {
	      if (!(*entp = (kadm5_principal_ent_t_v1)
		    malloc(sizeof(kadm5_principal_ent_rec_v1))))
		   return ENOMEM;
	      /* this memcpy works because the v1 structure is an initial
		 subset of the v2 struct.  C guarantees that this will
		 result in the same layout in memory */
	      memcpy(*entp, &r->rec, sizeof(**entp));
	 } else {
	    *entp = NULL;
	 }
    } else {
	 if (r->code == 0)
	      memcpy(ent, &r->rec, sizeof(r->rec));
    }
    
    return r->code;
}

kadm5_ret_t
kadm5_get_principals(void *server_handle,
			  char *exp, char ***princs, int *count)
{
    gprincs_arg	arg;
    gprincs_ret	*r;
    kadm5_server_handle_t handle = server_handle;

    CHECK_HANDLE(server_handle);

    if(princs == NULL || count == NULL)
	return EINVAL;
    arg.exp = exp;
    arg.api_version = handle->api_version;
    r = get_princs_2(&arg, handle->clnt);
    if(r == NULL)
	eret();
    if(r->code == 0) {
	 *count = r->count;
	 *princs = r->princs;
    } else {
	 *count = 0;
	 *princs = NULL;
    }
    
    return r->code;
}

kadm5_ret_t
kadm5_rename_principal(void *server_handle,
			    krb5_principal source, krb5_principal dest)
{
    rprinc_arg		arg;
    generic_ret		*r;
    kadm5_server_handle_t handle = server_handle;

    CHECK_HANDLE(server_handle);

    arg.src = source;
    arg.dest = dest;
    arg.api_version = handle->api_version;
    if (source == NULL || dest == NULL)
	return EINVAL;
    r = rename_principal_2(&arg, handle->clnt);
    if(r == NULL)
	eret();        
    return r->code;
}

kadm5_ret_t
kadm5_chpass_principal(void *server_handle,
			    krb5_principal princ, char *password)
{
    chpass_arg		arg;
    generic_ret		*r;
    kadm5_server_handle_t handle = server_handle;

    CHECK_HANDLE(server_handle);

    arg.princ = princ;
    arg.pass = password;
    arg.api_version = handle->api_version;

    if(princ == NULL)
	return EINVAL;
    r = chpass_principal_2(&arg, handle->clnt);
    if(r == NULL)
	eret();        
    return r->code;
}

kadm5_ret_t
kadm5_chpass_principal_3(void *server_handle,
			 krb5_principal princ, krb5_boolean keepold,
			 int n_ks_tuple, krb5_key_salt_tuple *ks_tuple,
			 char *password)
{
    chpass3_arg		arg;
    generic_ret		*r;
    kadm5_server_handle_t handle = server_handle;

    CHECK_HANDLE(server_handle);

    arg.princ = princ;
    arg.pass = password;
    arg.api_version = handle->api_version;
    arg.keepold = keepold;
    arg.n_ks_tuple = n_ks_tuple;
    arg.ks_tuple = ks_tuple;

    if(princ == NULL)
	return EINVAL;
    r = chpass_principal3_2(&arg, handle->clnt);
    if(r == NULL)
	eret();        
    return r->code;
}

kadm5_ret_t
kadm5_setv4key_principal(void *server_handle,
			 krb5_principal princ,
			 krb5_keyblock *keyblock)
{
    setv4key_arg	arg;
    generic_ret		*r;
    kadm5_server_handle_t handle = server_handle;

    CHECK_HANDLE(server_handle);

    arg.princ = princ;
    arg.keyblock = keyblock;
    arg.api_version = handle->api_version;

    if(princ == NULL || keyblock == NULL)
	return EINVAL;
    r = setv4key_principal_2(&arg, handle->clnt);
    if(r == NULL)
	eret();        
    return r->code;
}

kadm5_ret_t
kadm5_setkey_principal(void *server_handle,
		       krb5_principal princ,
		       krb5_keyblock *keyblocks,
		       int n_keys)
{
    setkey_arg		arg;
    generic_ret		*r;
    kadm5_server_handle_t handle = server_handle;

    CHECK_HANDLE(server_handle);

    arg.princ = princ;
    arg.keyblocks = keyblocks;
    arg.n_keys = n_keys;
    arg.api_version = handle->api_version;

    if(princ == NULL || keyblocks == NULL)
	return EINVAL;
    r = setkey_principal_2(&arg, handle->clnt);
    if(r == NULL)
	eret();        
    return r->code;
}

kadm5_ret_t
kadm5_setkey_principal_3(void *server_handle,
			 krb5_principal princ,
			 krb5_boolean keepold, int n_ks_tuple,
			 krb5_key_salt_tuple *ks_tuple,
			 krb5_keyblock *keyblocks,
			 int n_keys)
{
    setkey3_arg		arg;
    generic_ret		*r;
    kadm5_server_handle_t handle = server_handle;

    CHECK_HANDLE(server_handle);

    arg.princ = princ;
    arg.keyblocks = keyblocks;
    arg.n_keys = n_keys;
    arg.api_version = handle->api_version;
    arg.keepold = keepold;
    arg.n_ks_tuple = n_ks_tuple;
    arg.ks_tuple = ks_tuple;

    if(princ == NULL || keyblocks == NULL)
	return EINVAL;
    r = setkey_principal3_2(&arg, handle->clnt);
    if(r == NULL)
	eret();        
    return r->code;
}

kadm5_ret_t
kadm5_randkey_principal_3(void *server_handle,
			  krb5_principal princ,
			  krb5_boolean keepold, int n_ks_tuple,
			  krb5_key_salt_tuple *ks_tuple,
			  krb5_keyblock **key, int *n_keys)
{
    chrand3_arg		arg;
    chrand_ret		*r;
    kadm5_server_handle_t handle = server_handle;
    int			i, ret;

    CHECK_HANDLE(server_handle);

    arg.princ = princ;
    arg.api_version = handle->api_version;
    arg.keepold = keepold;
    arg.n_ks_tuple = n_ks_tuple;
    arg.ks_tuple = ks_tuple;

    if(princ == NULL)
	return EINVAL;
    r = chrand_principal3_2(&arg, handle->clnt);
    if(r == NULL)
	eret();
    if (handle->api_version == KADM5_API_VERSION_1) {
	 if (key)
	      krb5_copy_keyblock(handle->context, &r->key, key);
    } else {
	 if (n_keys)
	      *n_keys = r->n_keys;
	 if (key) {
	      if(r->n_keys) {
		      *key = (krb5_keyblock *) 
			      malloc(r->n_keys*sizeof(krb5_keyblock));
		      if (*key == NULL)
			      return ENOMEM;
		      for (i = 0; i < r->n_keys; i++) {
			      ret = krb5_copy_keyblock_contents(handle->context,
								&r->keys[i],
								&(*key)[i]);
			      if (ret) {
				      free(*key);
				      return ENOMEM;
			      }
		      }
	      } else *key = NULL;
         }
    }

    return r->code;
}

kadm5_ret_t
kadm5_randkey_principal(void *server_handle,
			krb5_principal princ,
			krb5_keyblock **key, int *n_keys)
{
    chrand_arg		arg;
    chrand_ret		*r;
    kadm5_server_handle_t handle = server_handle;
    int			i, ret;

    CHECK_HANDLE(server_handle);

    arg.princ = princ;
    arg.api_version = handle->api_version;

    if(princ == NULL)
	return EINVAL;
    r = chrand_principal_2(&arg, handle->clnt);
    if(r == NULL)
	eret();
    if (handle->api_version == KADM5_API_VERSION_1) {
	 if (key)
	      krb5_copy_keyblock(handle->context, &r->key, key);
    } else {
	 if (n_keys)
	      *n_keys = r->n_keys;
	 if (key) {
	      if(r->n_keys) {
		      *key = (krb5_keyblock *) 
			      malloc(r->n_keys*sizeof(krb5_keyblock));
		      if (*key == NULL)
			      return ENOMEM;
		      for (i = 0; i < r->n_keys; i++) {
			      ret = krb5_copy_keyblock_contents(handle->context,
								&r->keys[i],
								&(*key)[i]);
			      if (ret) {
				      free(*key);
				      return ENOMEM;
			      }
		      }
	      } else *key = NULL;
         }
    }

    return r->code;
}

/* not supported on client side */
kadm5_ret_t kadm5_decrypt_key(void *server_handle,
			      kadm5_principal_ent_t entry, krb5_int32
			      ktype, krb5_int32 stype, krb5_int32
			      kvno, krb5_keyblock *keyblock,
			      krb5_keysalt *keysalt, int *kvnop)
{
     return EINVAL;
}
