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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 */

#define NEED_WINDOWS
#include "stdcc.h"
#include "stdcc_util.h"
#include "string.h"
#include "k5-int.h"
#include <stdio.h>

apiCB *gCntrlBlock = NULL;

#if defined(_WIN32)
#include "winccld.h"	
#endif

#ifndef CC_API_VER2
#define CC_API_VER2
#endif

#ifdef DEBUG
#if defined(_WIN32)
#include <io.h>
#define SHOW_DEBUG(buf)   MessageBox((HWND)NULL, (buf), "ccapi debug", MB_OK)
#endif
	/* XXX need macintosh debugging statement if we want to debug */
	/* on the mac */
#else
#define SHOW_DEBUG(buf)
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

#if defined(_WIN32)
/*
 * cache_changed be called after the cache changes.
 * A notification message is is posted out to all top level
 * windows so that they may recheck the cache based on the
 * changes made.  We register a unique message type with which
 * we'll communicate to all other processes. 
 */
void cache_changed()
{
	static unsigned int message = 0;
	
	if (message == 0)
		message = RegisterWindowMessage(WM_KERBEROS5_CHANGED);

	PostMessage(HWND_BROADCAST, message, 0, 0);
}
#else /* _WIN32 */

void cache_changed()
{
	return;
}
#endif /* _WIN32 */

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
	{ CC_NO_EXIST,				KRB5_FCC_NOFILE },
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

	if (err == CC_NOERROR)
		return 0;

	for (p = err_xlate_table; p->cc_err; p++) {
		if (err == p->cc_err)
			return p->krb5_err;
	}
	return KRB5_FCC_INTERNAL; /* XXX we need a miscellaneous return */
}

static krb5_error_code stdcc_setup(krb5_context context,
				   stdccCacheDataPtr ccapi_data)
{
	int	err;

  	/* make sure the API has been intialized */
  	if (gCntrlBlock == NULL) {
#ifdef CC_API_VER2
		err = cc_initialize(&gCntrlBlock, CC_API_VER_2, NULL, NULL);
#else
		err = cc_initialize(&gCntrlBlock, CC_API_VER_1, NULL, NULL);
#endif
		if (err != CC_NOERROR)
			return cc_err_xlate(err);
	}

	/*
	 * No ccapi_data structure, so we don't need to make sure the
	 * ccache exists.
	 */
	if (!ccapi_data)
		return 0;

	/*
	 * The ccache already exists
	 */
	if (ccapi_data->NamedCache)
		return 0;

	err = cc_open(gCntrlBlock, ccapi_data->cache_name,
		      CC_CRED_V5, 0L, &ccapi_data->NamedCache);
	if (err == CC_NOTFOUND)
	  err = CC_NO_EXIST;
	if (err == CC_NOERROR)
		return 0;

	ccapi_data->NamedCache = NULL;
	return cc_err_xlate(err);
}

void krb5_stdcc_shutdown()
{
	if (gCntrlBlock)
		cc_shutdown(&gCntrlBlock);
	gCntrlBlock = 0;
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
	krb5_error_code		retval;
	stdccCacheDataPtr	ccapi_data = NULL;
	char 			*name = NULL;
	cc_time_t 		time;
	int 			err;

	if ((retval = stdcc_setup(context, NULL)))
		return retval;
	
	retval = KRB5_CC_NOMEM;
	if (!(newCache = (krb5_ccache) malloc(sizeof(struct _krb5_ccache))))
		goto errout;
  	if (!(ccapi_data = (stdccCacheDataPtr)malloc(sizeof(stdccCacheData))))
		goto errout;
	if (!(name = malloc(256)))
		goto errout;
	
  	/* create a unique name */
  	cc_get_change_time(gCntrlBlock, &time);
  	sprintf(name, "gen_new_cache%d", time);
  	
  	/* create the new cache */
  	err = cc_create(gCntrlBlock, name, name, CC_CRED_V5, 0L,
			&ccapi_data->NamedCache);
	if (err != CC_NOERROR) {
		retval = cc_err_xlate(err);
		goto errout;
	}

  	/* setup some fields */
  	newCache->ops = &krb5_cc_stdcc_ops;
  	newCache->data = ccapi_data;
	ccapi_data->cache_name = name;
  	
  	/* return a pointer to the new cache */
	*id = newCache;
	  	
	return 0;

errout:
	if (newCache)
		free(newCache);
	if (ccapi_data)
		free(ccapi_data);
	if (name)
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
	char 			*cName = NULL;
	
	if ((retval = stdcc_setup(context, NULL)))
		return retval;
	
	retval = KRB5_CC_NOMEM;
	if (!(newCache = (krb5_ccache) malloc(sizeof(struct _krb5_ccache))))
		goto errout;
  	
  	if (!(ccapi_data = (stdccCacheDataPtr)malloc(sizeof(stdccCacheData))))
		goto errout;

	if (!(cName = malloc(strlen(residual)+1)))
		goto errout;
	
  	newCache->ops = &krb5_cc_stdcc_ops;
	newCache->data = ccapi_data;
	ccapi_data->cache_name = cName;

	strcpy(cName, residual);
	
 	err = cc_open(gCntrlBlock, cName, CC_CRED_V5, 0L,
		      &ccapi_data->NamedCache);
	if (err != CC_NOERROR)
		ccapi_data->NamedCache = NULL;
	
  	/* return new cache structure */
	*id = newCache;
	
  	return 0;
	
errout:
	if (newCache)
		free(newCache);
	if (ccapi_data)
		free(ccapi_data);
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
  	
	if ((retval = stdcc_setup(context, NULL)))
		return retval;
	
  	/* test id for null */
  	if (id == NULL) return KRB5_CC_NOMEM;
  	
	if ((retval = krb5_unparse_name(context, princ, &cName)))
		return retval;

	ccapi_data = id->data;


	if (ccapi_data->NamedCache)
		cc_close(gCntrlBlock, &ccapi_data->NamedCache);

	err = cc_create(gCntrlBlock, ccapi_data->cache_name, cName,
			CC_CRED_V5, 0L, &ccapi_data->NamedCache);
	if (err != CC_NOERROR) {
		krb5_free_unparsed_name(context, cName);
		return cc_err_xlate(err);
	}

#if 0
	/*
	 * Some implementations don't set the principal name
	 * correctly, so we force set it to the correct value.
	 */
	err = cc_set_principal(gCntrlBlock, ccapi_data->NamedCache,
			       CC_CRED_V5, cName);
#endif
	krb5_free_unparsed_name(context, cName);
	cache_changed();
	
	return cc_err_xlate(err);
}

/*
 * store
 *
 * store some credentials in our cache
 */
krb5_error_code KRB5_CALLCONV krb5_stdcc_store 
        (krb5_context context, krb5_ccache id, krb5_creds *creds )
{
	krb5_error_code	retval;
	stdccCacheDataPtr	ccapi_data = id->data;
	cred_union *cu = NULL;
	int err;

	if ((retval = stdcc_setup(context, ccapi_data)))
		return retval;
	
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
		
	/* free the cred union using our local version of cc_free_creds()
	   since we allocated it locally */
	err = krb5_free_cc_cred_union(&cu);
		 
	cache_changed();
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
	stdccCacheDataPtr	ccapi_data = id->data;
	krb5_error_code	retval;
	int	err;
	ccache_cit	*iterator;

	if ((retval = stdcc_setup(context, ccapi_data)))
		return retval;

#ifdef CC_API_VER2
	err = cc_seq_fetch_creds_begin(gCntrlBlock, ccapi_data->NamedCache,
				       &iterator);
	if (err != CC_NOERROR)
		return cc_err_xlate(err);
	*cursor = iterator;
#else
	/* all we have to do is initialize the cursor */
	*cursor = NULL;
#endif
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
	krb5_error_code	retval;
	stdccCacheDataPtr	ccapi_data = id->data;
	int err;
	cred_union *credU = NULL;
	ccache_cit	*iterator;
	
	if ((retval = stdcc_setup(context, ccapi_data)))
		return retval;
	
#ifdef CC_API_VER2
	iterator = *cursor;
	if (iterator == 0)
		return KRB5_CC_END;
	err = cc_seq_fetch_creds_next(gCntrlBlock, &credU, iterator);

	if (err == CC_END) {
		cc_seq_fetch_creds_end(gCntrlBlock, &iterator);
		*cursor = 0;
	}
#else
	err = cc_seq_fetch_creds(gCntrlBlock, ccapi_data->NamedCache,
				 &credU, (ccache_cit **)cursor); 
#endif

	if (err != CC_NOERROR)
		return cc_err_xlate(err);
	
	/* copy data	(with translation) */
	dupCCtoK5(context, credU->cred.pV5Cred, creds);
	
	/* free our version of the cred - okay to use cc_free_creds() here
	   because we got it from the CCache library */
	cc_free_creds(gCntrlBlock, &credU);
	
	return 0;
}


/*
 * retreive
 *
 * - try to find a matching credential in the cache
 */
#if 0
krb5_error_code KRB5_CALLCONV krb5_stdcc_retrieve 
       		(krb5_context context, 
		   krb5_ccache id, 
		   krb5_flags whichfields, 
		   krb5_creds *mcreds, 
		   krb5_creds *creds )
{
	krb5_error_code	retval;
	krb5_cc_cursor curs = NULL;
	krb5_creds *fetchcreds;
		
	if ((retval = stdcc_setup(context, NULL)))
		return retval;
	
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
#else
#include "k5-int.h"

krb5_error_code KRB5_CALLCONV
krb5_stdcc_retrieve(context, id, whichfields, mcreds, creds)
   krb5_context context;
   krb5_ccache id;
   krb5_flags whichfields;
   krb5_creds *mcreds;
   krb5_creds *creds;
{
    return krb5_cc_retrieve_cred_default (context, id, whichfields,
					  mcreds, creds);
}

#endif

/*
 *  end seq
 *
 * just free up the storage assoicated with the cursor (if we could)
 */
krb5_error_code KRB5_CALLCONV krb5_stdcc_end_seq_get 
        (krb5_context context, krb5_ccache id, krb5_cc_cursor *cursor)
{
	krb5_error_code		retval;
	stdccCacheDataPtr	ccapi_data = NULL;
	int			err;
#ifndef CC_API_VER2
	cred_union 		*credU = NULL;
#endif

	ccapi_data = id->data;
	
	if ((retval = stdcc_setup(context, ccapi_data)))
		return retval;

	if (*cursor == NULL)
		return 0;

#ifdef CC_API_VER2
	err = cc_seq_fetch_creds_end(gCntrlBlock, (ccache_cit **)cursor);
	if (err != CC_NOERROR)
		return cc_err_xlate(err);
#else	
	/*
	 * Finish calling cc_seq_fetch_creds to clear out the cursor
	 */
	while (*cursor) {
		err = cc_seq_fetch_creds(gCntrlBlock, ccapi_data->NamedCache,
				 &credU, (ccache_cit **)cursor);
		if (err)
			break;
		
		/* okay to call cc_free_creds() here because we got credU from CCache lib */
		cc_free_creds(gCntrlBlock, &credU);
	}
#endif
	
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
	krb5_error_code	retval;
	stdccCacheDataPtr	ccapi_data = id->data;

	if ((retval = stdcc_setup(context, NULL)))
		return retval;
	
	/* free it */
	
	if (ccapi_data) {
		if (ccapi_data->cache_name)
			free(ccapi_data->cache_name);
		if (ccapi_data->NamedCache)
			cc_close(gCntrlBlock, &ccapi_data->NamedCache);
		free(ccapi_data);
		id->data = NULL;
	}
	free(id);
	
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
	krb5_error_code	retval;
	stdccCacheDataPtr	ccapi_data = id->data;

	if ((retval = stdcc_setup(context, ccapi_data))) {
		return retval;
	}

	/* free memory associated with the krb5_ccache */
	if (ccapi_data) {
		if (ccapi_data->cache_name)
			free(ccapi_data->cache_name);
		if (ccapi_data->NamedCache) {
			/* destroy the named cache */
			err = cc_destroy(gCntrlBlock, &ccapi_data->NamedCache);
			retval = cc_err_xlate(err);
			cache_changed();
		}
		free(ccapi_data);
		id->data = NULL;
	}
	free(id);

	/* If the cache does not exist when we tried to destroy it,
	   that's fine.  That means someone else destryoed it since
	   we resolved it. */
	if (retval == KRB5_FCC_NOFILE)
		return 0;
	return retval;
}

/*
 *  getname
 *
 * - return the name of the named cache
 */
const char * KRB5_CALLCONV krb5_stdcc_get_name 
        (krb5_context context, krb5_ccache id )
{
	stdccCacheDataPtr	ccapi_data = id->data;

	if (!ccapi_data)
		return 0;

	return (ccapi_data->cache_name);
}


/* get_principal
 *
 * - return the principal associated with the named cache
 */
krb5_error_code KRB5_CALLCONV krb5_stdcc_get_principal
	(krb5_context context, krb5_ccache id , krb5_principal *princ) 
{
	int 			err;
	char 	  		*name = NULL;
	stdccCacheDataPtr	ccapi_data = id->data;
	krb5_error_code		retval;
	
	if ((retval = stdcc_setup(context, ccapi_data)))
		return retval;

	/* another wrapper */
	err = cc_get_principal(gCntrlBlock, ccapi_data->NamedCache,
			       &name);

	if (err != CC_NOERROR) 
		return cc_err_xlate(err);
		
	/* turn it into a krb principal */
	err = krb5_parse_name(context, name, princ);

	cc_free_principal(gCntrlBlock, &name);
	
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
	stdccCacheDataPtr	ccapi_data = id->data;
	krb5_error_code		retval;
	
	if ((retval = stdcc_setup(context, ccapi_data)))
		return retval;

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
	stdccCacheDataPtr	ccapi_data = id->data;
	krb5_error_code		retval;
	
	if ((retval = stdcc_setup(context, ccapi_data))) {
		if (retval == KRB5_FCC_NOFILE)
			return 0;
		return retval;
	}
    	
    	/* convert to a cred union */
    	dupK5toCC(context, creds, &cu);
    	
    	/* remove it */
    	err = cc_remove_cred(gCntrlBlock, ccapi_data->NamedCache, *cu);
    	if (err != CC_NOERROR)
		return cc_err_xlate(err);
    	
    	/* free the cred union using our local version of cc_free_creds()
	       since we allocated it locally */
    	err = krb5_free_cc_cred_union(&cu);
	cache_changed();
    	if (err != CC_NOERROR)
		return cc_err_xlate(err);

        return 0;
}
