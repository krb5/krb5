/*
 * stdcc.c - additions to the Kerberos 5 library to support the memory
 *	 credentical cache API
 *	
 * Written by Frank Dabek July 1998
 *
 * Copyright 1998, 1999 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
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
 */

#include "stdcc.h"
#include "stdcc_util.h"
#include "string.h"
#include <stdio.h>

#if defined(_MSDOS) || defined(_WIN32)
apiCB *gCntrlBlock = NULL;
#endif

/*
 * declare our global object wanna-be
 * must be installed in ccdefops.c
 */

krb5_cc_ops krb5_cc_stdcc_ops = {
     0,
     "API",
      krb5_stdcc_get_name,
      krb5_stdcc_resolve,
      krb5_stdcc_generate_new,
      krb5_stdcc_initialize,
      krb5_stdcc_destroy,
      krb5_stdcc_close,
      krb5_stdcc_store,
      krb5_stdcc_retrieve,
      krb5_stdcc_get_principal,
      krb5_stdcc_start_seq_get,
      krb5_stdcc_next_cred,
      krb5_stdcc_end_seq_get,
      krb5_stdcc_remove, 
      krb5_stdcc_set_flags,
};

struct err_xlate
{
	int	cc_err;
	krb5_error_code	krb5_err;
};

static const struct err_xlate err_xlate_table[] =
{
	{ CC_BADNAME,				KRB5_CC_BADNAME },
	{ CC_NOTFOUND,				KRB5_CC_NOTFOUND },
	{ CC_END,				KRB5_CC_END },
	{ CC_IO,				KRB5_CC_IO },
	{ CC_WRITE,				KRB5_CC_WRITE },
	{ CC_NOMEM,				KRB5_CC_NOMEM },
	{ CC_FORMAT,				KRB5_CC_FORMAT },
	{ CC_WRITE,				KRB5_CC_WRITE },
	{ CC_LOCKED,				KRB5_FCC_INTERNAL /* XXX */ },
	{ CC_BAD_API_VERSION,			KRB5_FCC_INTERNAL /* XXX */ },
	{ CC_NO_EXIST,				KRB5_FCC_INTERNAL /* XXX */ },
	{ CC_NOT_SUPP,				KRB5_FCC_INTERNAL /* XXX */ },
	{ CC_BAD_PARM,				KRB5_FCC_INTERNAL /* XXX */ },
	{ CC_ERR_CACHE_ATTACH,			KRB5_FCC_INTERNAL /* XXX */ },
	{ CC_ERR_CACHE_RELEASE,			KRB5_FCC_INTERNAL /* XXX */ },
	{ CC_ERR_CACHE_FULL,			KRB5_FCC_INTERNAL /* XXX */ },
	{ CC_ERR_CRED_VERSION,			KRB5_FCC_INTERNAL /* XXX */ },
	{ 0,					0 }
};

static krb5_error_code cc_err_xlate(int err)
{
	const struct err_xlate *p;

	for (p = err_xlate_table; p->e2err; p++) {
		if (err == p->e2err)
			return p->pqerr;
	}
	return KRB5_FCC_INTERNAL; /* XXX we need a miscellaneous return */
}

/*
 * -- generate_new --------------------------------
 * 
 * create a new cache with a unique name, corresponds to creating a
 * named cache iniitialize the API here if we have to.
 */
krb5_error_code KRB5_CALLCONV  krb5_stdcc_generate_new 
	(krb5_context context, krb5_ccache *id ) 
{
  	krb5_ccache 		newCache = NULL;
	stdccCacheDataPtr	ccapi_data = NULL;
	char 			*name = NULL;
	cc_time_t 		time;
	int 			err;
	
  	/* make sure the API has been intialized */
  	if (gCntrlBlock == NULL) {
		err = cc_initialize(&gCntrlBlock, CC_API_VER_1, NULL, NULL);
		if (err != CC_NOERROR)
			return cc_err_xlate(err);
	}
  	
	retval = KRB5_CC_NOMEM;
	if (!(newCache = (krb5_ccache) malloc(sizeof(struct _krb5_ccache))))
		goto errout;
  	if (!(ccapi_ptr = (stdccCacheDataPtr)malloc(sizeof(stdccCacheData))))
		goto errout;
	if (!(cName = malloc(strlen(residual)+1)))
		goto errout;
	
  	/* create a unique name */
  	cc_get_change_time(gCntrlBlock, &time);
  	sprintf(name, "gen_new_cache%d", time);
  	
  	//create the new cache
  	err = cc_create(gCntrlBlock, name, name, CC_CRED_V5, 0L,
			&ccapi_data->NamedCache);
	if (err != CC_NOERROR) {
		retval = cc_err_xlate(err);
		goto errout;
	}
	
  	/* setup some fields */
  	newCache->ops = &krb5_cc_stdcc_ops;
  	newCache->data = ccapi_data;
	ccapi_data->ccache_name = name;
  	
  	/* return a pointer to the new cache */
	*id = newCache;
	  	
	return 0;

errout:
	if (newCache)
		free(newCache);
	if (ccapi_ptr)
		free(ccapi_ptr);
	if (cName)
		free(name);
	return retval;
}
  
/*
 * resolve
 *
 * create a new cache with the name stored in residual
 */
krb5_error_code KRB5_CALLCONV  krb5_stdcc_resolve 
        (krb5_context context, krb5_ccache *id , const char *residual ) 
{
	krb5_ccache 		newCache = NULL;
	stdccCacheDataPtr	ccapi_data = NULL;
	int 			err;
	krb5_error_code		retval;
	char 			*cName;
	
  	/* make sure the API has been intialized */
  	if (gCntrlBlock == NULL) {
		err = cc_initialize(&gCntrlBlock, CC_API_VER_1, NULL, NULL);
		if (err != CC_NOERROR)
			return cc_err_xlate(err);
	}

	retval = KRB5_CC_NOMEM;
	if (!(newCache = (krb5_ccache) malloc(sizeof(struct _krb5_ccache))))
		goto errout;
  	
  	if (!(ccapi_ptr = (stdccCacheDataPtr)malloc(sizeof(stdccCacheData))))
		goto errout;

	if (!(cName = malloc(strlen(residual)+1)))
		goto errout;
	
  	newCache->ops = &krb5_cc_stdcc_ops;
	newCache->data = ccapi_ptr;
	ccapi_ptr->ccache_name = cName;

	strcpy(cName, residual);
	
 	err = cc_open(gCntrlBlock, cName, CC_CRED_V5, 0L,
		      &ccapi_ptr->NamedCache);
	if (err != CC_NOERROR)
		ccapi_ptr->NamedCache = NULL;
	
  	/* return new cache structure */
	*id = newCache;
	
  	return 0;
	
errout:
	if (newCache)
		free(newCache);
	if (ccapi_ptr)
		free(ccapi_ptr);
	if (cName)
		free(cName);
	return retval;
}
  
/*
 * initialize
 *
 * initialize the cache, check to see if one already exists for this
 * principal if not set our principal to this principal. This
 * searching enables ticket sharing
 */
krb5_error_code KRB5_CALLCONV  krb5_stdcc_initialize 
       (krb5_context context, krb5_ccache id,  krb5_principal princ) 
{
	stdccCacheDataPtr	ccapi_data = NULL;
  	int 			err;
  	char 			*cName = NULL;
	krb5_error_code		retval;
  	
  	/* test id for null */
  	if (id == NULL) return KRB5_CC_NOMEM;
  	
  	/* test for initialized API */
  	if (gCntrlBlock == NULL)
  		return KRB5_FCC_INTERNAL; /* XXX better error code? */

	if ((retval = krb5_unparse_name(context, princ, &cName)))
		return retval;

	ccapi_data = id->data;

	if (!ccapi_data->NamedCache) {
		err = cc_open(gCntrlBlock, ccapi_data->cache_name,
			      CC_CRED_V5, 0L, 
			      &ccapi_data->NamedCache);
		if (err != CC_NO_ERROR)
			ccapi_data->NamedCache = NULL;
	}

	if (ccapi_data->NamedCache)
		cc_destroy(gCntrlBlock, &ccapi_data->NamedCache);

	err = cc_create(gCntrlBlock, ccapi_data->ccache_name, cName,
			CC_CRED_V5, 0L, &ccapi_data->NamedCache);
	krb5_free_unparsed_name(context, cName);
	
	if (err)
		return cc_err_xlate(err);
	
	return 0;
}

/*
 * store
 *
 * store some credentials in our cache
 */
krb5_error_code KRB5_CALLCONV krb5_stdcc_store 
        (krb5_context context, krb5_ccache id , krb5_creds *creds )
{
	stdccCacheDataPtr	ccapi_data = id->data;
	cred_union *cu = NULL;
	int err;
       
	/* test for initialized API */
	if (gCntrlBlock == NULL)
  		return KRB5_FCC_INTERNAL; /* XXX better error code? */

	/* copy the fields from the almost identical structures */
	dupK5toCC(context, creds, &cu);
			
	/*
	 * finally store the credential
	 * store will copy (that is duplicate) everything
	 */
	err = cc_store(gCntrlBlock,
		       ((stdccCacheDataPtr)(id->data))->NamedCache, *cu);
	if (err != CC_NOERROR)
		return cc_err_xlate(err);
		
	/* free the cred union */
	err = cc_free_creds(gCntrlBlock, &cu);
		 
	return err;
}

/*
 * start_seq_get
 *
 * begin an iterator call to get all of the credentials in the cache
 */
krb5_error_code KRB5_CALLCONV krb5_stdcc_start_seq_get 
(krb5_context context, krb5_ccache id , krb5_cc_cursor *cursor )
{
	/* all we have to do is initialize the cursor */
	*cursor = NULL;
	return 0;
}

/*
 * next cred
 * 
 * - get the next credential in the cache as part of an iterator call
 * - this maps to call to cc_seq_fetch_creds
 */
krb5_error_code KRB5_CALLCONV krb5_stdcc_next_cred 
        (krb5_context context, krb5_ccache id,  krb5_cc_cursor *cursor, 
	 krb5_creds *creds)
{
	int err;
	cred_union *credU = NULL;
	
	/* test for initialized API */
	if (gCntrlBlock == NULL)
  		return KRB5_FCC_INTERNAL; /* XXX better error code? */

	err = cc_seq_fetch_creds(gCntrlBlock,
				 ((stdccCacheDataPtr)(id->data))->NamedCache,
				 &credU, (ccache_cit **)cursor);
	
	if (err != CC_NOERROR)
		return cc_err_xlate(err);

	/* copy data	(with translation) */
	dupCCtoK5(context, credU->cred.pV5Cred, creds);
	
	/* free our version of the cred */
	cc_free_creds(gCntrlBlock, &credU);
	
	return 0;
}


/*
 * retreive
 *
 * - try to find a matching credential in the cache
 */
krb5_error_code KRB5_CALLCONV krb5_stdcc_retrieve 
       		(krb5_context context, 
		   krb5_ccache id, 
		   krb5_flags whichfields, 
		   krb5_creds *mcreds, 
		   krb5_creds *creds )
{
	krb5_cc_cursor curs = NULL;
	krb5_creds *fetchcreds;
		
	fetchcreds = (krb5_creds *)malloc(sizeof(krb5_creds));
  	if (fetchcreds == NULL) return KRB5_CC_NOMEM;
	
	/* we're going to use the iterators */
	krb5_stdcc_start_seq_get(context, id, &curs);
	
	while (!krb5_stdcc_next_cred(context, id, &curs, fetchcreds)) {
		/*
		 * look at each credential for a match
		 * use this match routine since it takes the
		 * whichfields and the API doesn't
		 */
		if (stdccCredsMatch(context, fetchcreds,
				    mcreds, whichfields)) {
			/* we found it, copy and exit */
			*creds = *fetchcreds;
			krb5_stdcc_end_seq_get(context, id, &curs);
			return 0;
		}
		/* free copy allocated by next_cred */
		krb5_free_cred_contents(context, fetchcreds);
	}
		
	/* no luck, end get and exit */
	krb5_stdcc_end_seq_get(context, id, &curs);
	
	/* we're not using this anymore so we should get rid of it! */
	free(fetchcreds);
	
	return KRB5_CC_NOTFOUND;
}

/*
 *  end seq
 *
 * just free up the storage assoicated with the cursor (if we could)
 */
krb5_error_code KRB5_CALLCONV krb5_stdcc_end_seq_get 
        (krb5_context context, krb5_ccache id, krb5_cc_cursor *cursor)
{
        
	/*
	 * the limitation of the Ccache api and the seq calls
	 * causes trouble. cursor might have already been freed
	 * and anyways it is in the mac's heap so we need FreePtr
	 * but all i have is free
	 */
	/* FreePtr(*cursor); */
      
	/* LEAK IT! */
	*cursor = NULL;

	return(0);
}
     
/*
 * close
 *
 * - free our pointers to the NC
 */
krb5_error_code KRB5_CALLCONV 
krb5_stdcc_close(krb5_context context, krb5_ccache id)
{
	/* free it */
	
	if (id->data != NULL) {
		free((stdccCacheDataPtr)(id->data));
		/* null it out */
		(stdccCacheDataPtr)(id->data) = NULL;
	}
	
	/*
	 * I suppose we ought to check if id is null before doing
	 * this, but no other place in krb5 does... -smcguire
	 */
	free(id);
	
	id = NULL;
	
	return 0;
}

/*
 * destroy
 *
 * - free our storage and the cache
 */
krb5_error_code KRB5_CALLCONV
krb5_stdcc_destroy (krb5_context context, krb5_ccache id)
{

	int err;
	
	/* test for initialized API */
	if (gCntrlBlock == NULL)
  		return KRB5_FCC_INTERNAL; /* XXX better error code? */

	/* destroy the named cache */
	err = cc_destroy(gCntrlBlock,
			 &(((stdccCacheDataPtr)(id->data))->NamedCache));
	
	/* free the pointer to the record that held the pointer to the cache */
	free((stdccCacheDataPtr)(id->data));
	
	/* null it out */
	(stdccCacheDataPtr)(id->data) = NULL;
	
	return err;
}

/*
 *  getname
 *
 * - return the name of the named cache
 */
char * KRB5_CALLCONV krb5_stdcc_get_name 
        (krb5_context context, krb5_ccache id )
{
	char *ret = NULL;
	int err;
	
	/* test for initialized API */
	if (gCntrlBlock == NULL)
  		return NULL;
	
	/* just a wrapper */
	err = cc_get_name(gCntrlBlock,
			  (((stdccCacheDataPtr)(id->data))->NamedCache), &ret);
	
	if (err != CC_NOERROR)
		return ret;
	else
		return NULL;
}

/* get_principal
 *
 * - return the principal associated with the named cache
 */
krb5_error_code KRB5_CALLCONV krb5_stdcc_get_principal
	(krb5_context context, krb5_ccache id , krb5_principal *princ) 
{
	int err;
	char *name = NULL;
	
	/* test for initialized API */
	if (gCntrlBlock == NULL)
  		return KRB5_FCC_INTERNAL; /* XXX better error code? */

	/* another wrapper */
	err = cc_get_principal(gCntrlBlock,
			       (((stdccCacheDataPtr)(id->data))->NamedCache),
			       &name);

	if (err != CC_NOERROR) 
		return cc_err_xlate(err);
		
	/* turn it into a krb principal */
	err = krb5_parse_name(context, name, princ);
	
#if defined(macintosh)
	/*
	 * have to do something special on the Mac because name has
	 * been allocated with
	 * Mac memory routine NewPtr and held in memory
	 */
	if (name != NULL) {
		UnholdMemory(name,GetPtrSize(name));
		DisposePtr(name);
	}
#else
	if (name != NULL)
		free(name);
#endif

	return err;	
}

/*
 * set_flags
 *
 * - currently a NOP since we don't store any flags in the NC
 */
krb5_error_code KRB5_CALLCONV krb5_stdcc_set_flags 
        (krb5_context context, krb5_ccache id , krb5_flags flags)
{
	return 0;
}

/*
 * remove
 *
 * - remove the specified credentials from the NC
 */
krb5_error_code KRB5_CALLCONV krb5_stdcc_remove 
        (krb5_context context, krb5_ccache id,
	 krb5_flags flags, krb5_creds *creds)
{
    	cred_union *cu = NULL;
    	int err;
    	
	/* test for initialized API */
	if (gCntrlBlock == NULL)
  		return KRB5_FCC_INTERNAL; /* XXX better error code? */

    	/* convert to a cred union */
    	dupK5toCC(context, creds, &cu);
    	
    	/* remove it */
    	err = cc_remove_cred(gCntrlBlock,
			     (((stdccCacheDataPtr)(id->data))->NamedCache),
			     *cu);
    	if (err != CC_NOERROR)
		return cc_err_xlate(err);
    	
    	/* free the temp cred union */
    	err = cc_free_creds(gCntrlBlock, &cu);
    	if (err != CC_NOERROR) return err;

        return 0;
}
     
