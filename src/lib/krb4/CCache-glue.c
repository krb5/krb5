/*
 * CCache-glue.c
 *
 * This file contains implementations of krb4 credentials cache operations in terms
 * of the CCache API (<http://www.umich.edu/~sgr/v4Cache/>).
 *
 * $Header$
 */


#include "krb.h"
#include "krb4int.h"

#if !defined (USE_CCAPI) || !USE_CCAPI
#error "Cannot use CCache glue without the CCAPI!"
#endif

#ifdef USE_LOGIN_LIBRARY
#include <KerberosLoginPrivate.h>
#endif /* USE_LOGIN_LIBRARY */
#include <CredentialsCache.h>

#include <string.h>
#include <stdlib.h>
 
/*
 * The following functions are part of the KfM ABI.  
 * They are deprecated, so they only appear here, not in krb.h.
 *
 * Do not change the ABI of these functions!
 */
int KRB5_CALLCONV krb_get_num_cred(void);
int KRB5_CALLCONV krb_get_nth_cred(char *, char *, char *, int);
int KRB5_CALLCONV krb_delete_cred(char *, char *,char *);
int KRB5_CALLCONV dest_all_tkts(void);
 
/* Internal functions */
static void UpdateDefaultCache (void);

/* 
 * The way Kerberos v4 normally works is that at any given point in time there is a
 * file where all the tickets go, determined by an environment variable. If a user kinits
 * to a new principal, the existing tickets are replaced with new ones. At any point in time, there is a 
 * "current" or "default" principal, which is determined by the principal associated with
 * the current ticket file.
 * 
 * In the CCache API implementation, this corresponds to always having a "default"
 * or "current" named cache. The default principal then corresponds to that cache.
 *
 * Unfortunately, Kerberos v4 also has this notion that the default cache exists (in the sense
 * that its name is known) even before the actual file has been created.
 *
 * In addition to this, we cannot make the default cache system-wide global, because then
 * we get all sorts of interesting scenarios in which context switches between processes
 * can cause credentials to be stored in wrong caches.
 *
 * To solve all the problems, we have to emulate the concept of an environment variable,
 * by having a system-wide concept of what a default credentials cache is; then, we copy 
 * the system-wide value into the per-process value when the application starts up.
 *
 * However, in order to allow applications to be able to sanely handle the user model we
 * want to support, in which the user has some way of selecting the system-wide default
 * user _without_ quitting and relaunching all applications (this is also necessary for
 * KClient support), calls had to be added to the Kerberos v4 library to reset the 
 * per-process cached value of default cache.
 */
 
/*
 * Name of the default cache
 */
char* gDefaultCacheName = NULL;

/*
 * Initialize credentials cache
 *
 * Creating the cache will blow away an existing one. The assumption is that
 * whoever called us made sure that the one that we blow away if it exists
 * is the right one to blow away.
 */

int KRB5_CALLCONV
krb_in_tkt (
	char*		pname,
	char*		pinst,
	char*		realm)
{
	char			principal [MAX_K_NAME_SZ + 1];
	cc_int32		err = ccNoError;
	cc_context_t	cc_context = NULL;
    cc_int32		cc_version;
    cc_ccache_t		ccache = NULL;
	
	err = cc_initialize (&cc_context, ccapi_version_3, &cc_version, NULL);
    
	if (err == ccNoError) {
        sprintf (principal, "%s%s%s@%s", pname, (pinst [0] == '\0') ? "" : ".", pinst, realm);
	}
    
	if (err == ccNoError) {
        err = cc_context_create_ccache (cc_context, TKT_FILE, cc_credentials_v4, principal, &ccache);
	}

    if (ccache != NULL)
    	cc_ccache_release (ccache);
    if (cc_context != NULL)
        cc_context_release (cc_context);
    
    if (err != ccNoError)
		return KFAILURE;
    else
        return KSUCCESS;
}

int KRB5_CALLCONV
krb_save_credentials(
    char	*service,
    char	*instance,
    char	*realm,
    C_Block	session,
    int		lifetime,
    int		kvno,
    KTEXT	ticket,
    long	issue_date)
{
    return krb4int_save_credentials_addr(service, instance, realm,
					 session, lifetime, kvno,
					 ticket, issue_date, 0);
}

/*
 * Store a ticket into the default credentials cache
 * cache must exist (if it didn't exist, it would have been created by in_tkt)
 */
int
krb4int_save_credentials_addr(
	char*			service,
	char*			instance,
	char*			realm,
	C_Block			session,
	int				lifetime,
	int				kvno,
	KTEXT			ticket,
	long			issue_date,
	KRB_UINT32		local_address)
{
	cc_int32				cc_err = ccNoError;
	int						kerr = KSUCCESS;
	cc_credentials_v4_t		v4creds;
	cc_credentials_union	creds;
	cc_ccache_t				ccache = NULL;
	cc_string_t				principal;
	cc_context_t			cc_context = NULL;
    cc_int32				cc_version;
	
	cc_err = cc_initialize (&cc_context, ccapi_version_3, &cc_version, NULL);
	
	if (cc_err == ccNoError) {
        /* First try existing cache */
        cc_err = cc_context_open_ccache (cc_context, TKT_FILE, &ccache);
	}
	
    if (cc_err == ccNoError) {
        /* Now we have a cache. Fill out the credentials and put them in the cache. */
        /* To fill out the credentials, we need the principal */
        cc_err = cc_ccache_get_principal (ccache, cc_credentials_v4, &principal);
	}
    
    if (cc_err == ccNoError) {
        kerr = kname_parse (v4creds.principal, v4creds.principal_instance, v4creds.realm, (char*) principal -> data);
        cc_string_release (principal);
	}
    
	if ((cc_err == ccNoError) && (kerr == KSUCCESS)) {
		strncpy (v4creds.service, service, SNAME_SZ);
        strncpy (v4creds.service_instance, instance, INST_SZ);
        strncpy (v4creds.realm, realm, REALM_SZ);
        memmove (v4creds.session_key, session, sizeof (C_Block));
        v4creds.kvno = kvno;
        v4creds.string_to_key_type = cc_v4_stk_unknown;
        v4creds.issue_date = issue_date;
        v4creds.address = local_address;
        v4creds.lifetime = lifetime;
        v4creds.ticket_size = ticket -> length;
        memmove (v4creds.ticket, ticket -> dat, ticket -> length);
        
        creds.version = cc_credentials_v4;
        creds.credentials.credentials_v4 = &v4creds;
        
        cc_err = cc_ccache_store_credentials (ccache, &creds);
    }
	
    if (ccache != NULL)
        cc_ccache_release (ccache);
    if (cc_context != NULL)
        cc_context_release (cc_context);
    
    if (kerr != KSUCCESS)
        return kerr;
	if (cc_err != ccNoError)
		return KFAILURE;
    else
        return KSUCCESS;
}

/*
 * Credentials file -> realm mapping
 *
 * Determine the realm by opening the named cache and parsing realm from the principal
 */
int KRB5_CALLCONV
krb_get_tf_realm (
	const char*		ticket_file,
	char*			realm)
{
	cc_string_t		principal;
	char			pname [ANAME_SZ];
	char			pinst [INST_SZ];
	char			prealm [REALM_SZ];
    int				kerr = KSUCCESS;
	cc_int32		cc_err = ccNoError;
	cc_context_t	cc_context = NULL;
    cc_int32		cc_version = NULL;
    cc_ccache_t		ccache = NULL;
	
	cc_err = cc_initialize (&cc_context, ccapi_version_3, &cc_version, NULL);
	
    if (cc_err == ccNoError) {
        cc_err = cc_context_open_ccache (cc_context, ticket_file, &ccache);
	}

    if (cc_err == ccNoError) {
        cc_err = cc_ccache_get_principal (ccache, cc_credentials_v4, &principal);
	}

    if (cc_err == ccNoError) {
        /* found cache. get princiapl and parse it */
        kerr = kname_parse (pname, pinst, prealm, (char*) principal -> data);
        cc_string_release (principal);
    }
    
    if ((cc_err == ccNoError) && (kerr == KSUCCESS)) {
        strcpy (realm, prealm);
    }
    
    if (ccache != NULL) 
        cc_ccache_release (ccache);
    if (cc_context != NULL) 
        cc_context_release (cc_context);
    
    if (kerr != KSUCCESS)
        return kerr;
	if (cc_err != ccNoError)
		return GC_NOTKT;
    else
        return KSUCCESS;
}

/*
 * Credentials file -> name, instance, realm mapping
 */
int KRB5_CALLCONV
krb_get_tf_fullname (
	const char*		ticket_file,
	char*			name,
	char*			instance,
	char*			realm)
{
	cc_string_t		principal;
	int				kerr = KSUCCESS;
	cc_int32		cc_err = ccNoError;
	cc_context_t	cc_context = NULL;
    cc_int32		cc_version;
    cc_ccache_t		ccache = NULL;
	
	cc_err = cc_initialize (&cc_context, ccapi_version_3, &cc_version, NULL);
	
    if (cc_err == ccNoError) {
        cc_err = cc_context_open_ccache (cc_context, ticket_file, &ccache);
	}

    if (cc_err == ccNoError) {
        /* found cache. get principal and parse it */
        cc_err = cc_ccache_get_principal (ccache, cc_credentials_v4, &principal);
	}

    if (cc_err == ccNoError) {
        kerr = kname_parse (name, instance, realm, (char*) principal -> data);
        cc_string_release (principal);
	}
    
    if (ccache != NULL)
        cc_ccache_release (ccache);    
    if (cc_context != NULL)
        cc_context_release (cc_context);
    
    if (kerr != KSUCCESS)
        return kerr;
	if (cc_err != ccNoError)
		return GC_NOTKT;
    else
        return KSUCCESS;
}


/*
 * Retrieval from credentials cache
 */
int KRB5_CALLCONV
krb_get_cred (
	char*			service,
	char*			instance,
	char*			realm,
	CREDENTIALS*	creds)
{
	int							kerr = KSUCCESS;
    cc_int32					cc_err = ccNoError;
	cc_credentials_t			theCreds = NULL;
	cc_credentials_iterator_t	iterator = NULL;
	cc_context_t				cc_context = NULL;
    cc_int32					cc_version;
    cc_ccache_t					ccache = NULL;
		
#ifdef USE_LOGIN_LIBRARY
	// If we are requesting a tgt, prompt for it
	if (strncmp (service, KRB_TICKET_GRANTING_TICKET, ANAME_SZ) == 0) {
		OSStatus	err;
		char		*cacheName;
		KLPrincipal	outPrincipal;
		
		err = __KLInternalAcquireInitialTicketsForCache (TKT_FILE, kerberosVersion_V4, NULL, 
                                                                 &outPrincipal, &cacheName);

		if (err == klNoErr) {
                	krb_set_tkt_string (cacheName);		// Tickets for the krb4 principal went here
			KLDisposeString (cacheName);	
			KLDisposePrincipal (outPrincipal);
		} else {
			return GC_NOTKT;
		}
	}
#endif /* USE_LOGIN_LIBRARY */     
	
	cc_err = cc_initialize (&cc_context, ccapi_version_3, &cc_version, NULL);

	if (cc_err == ccNoError) {
        cc_err = cc_context_open_ccache (cc_context, TKT_FILE, &ccache);
	}

	if (cc_err == ccNoError) {
        cc_err = cc_ccache_new_credentials_iterator (ccache, &iterator);
	}

	if (cc_err == ccNoError) {
        for (;;) {
            /* get next creds */
            cc_err = cc_credentials_iterator_next (iterator, &theCreds);
            if (cc_err == ccIteratorEnd) {
                kerr = GC_NOTKT;
                break;
            }
            if (cc_err != ccNoError) {
                kerr = KFAILURE;
                break;
            }
            
            /* version, service, instance, realm check */
            if ((theCreds -> data -> version == cc_credentials_v4) &&
                (strcmp (theCreds -> data -> credentials.credentials_v4 -> service, service) == 0) &&
                (strcmp (theCreds -> data -> credentials.credentials_v4 -> service_instance, instance) == 0) &&
                (strcmp (theCreds -> data -> credentials.credentials_v4 -> realm, realm) == 0)) {
                
                /* Match! */
                strcpy (creds -> service, service);
                strcpy (creds -> instance, instance);
                strcpy (creds -> realm, realm);
                memmove (creds -> session, theCreds -> data -> credentials.credentials_v4 -> session_key, sizeof (C_Block));
                creds -> lifetime = theCreds -> data -> credentials.credentials_v4 -> lifetime;
                creds -> kvno = theCreds -> data -> credentials.credentials_v4 -> kvno;
                creds -> ticket_st.length = theCreds -> data -> credentials.credentials_v4 -> ticket_size;
                memmove (creds -> ticket_st.dat, theCreds -> data -> credentials.credentials_v4 -> ticket, creds -> ticket_st.length);
                creds -> issue_date = theCreds -> data -> credentials.credentials_v4 -> issue_date;
                strcpy (creds -> pname, theCreds -> data -> credentials.credentials_v4 -> principal);
                strcpy (creds -> pinst, theCreds -> data -> credentials.credentials_v4 -> principal_instance);
                creds -> stk_type = theCreds -> data -> credentials.credentials_v4 -> string_to_key_type;
                
                cc_credentials_release (theCreds);
                kerr = KSUCCESS;
                break;
            } else  {
                cc_credentials_release (theCreds);
            }
        }
	}
    
    if (iterator != NULL)
        cc_credentials_iterator_release (iterator);
    if (ccache != NULL)
        cc_ccache_release (ccache);    
    if (cc_context != NULL)
        cc_context_release (cc_context);
    
    if (kerr != KSUCCESS)
        return kerr;
	if (cc_err != ccNoError)
		return GC_NOTKT;
    else
        return KSUCCESS;
}


/*
 * Getting name of default credentials cache
 */
const char* KRB5_CALLCONV
tkt_string (void)
{
	if (gDefaultCacheName == NULL) {
        UpdateDefaultCache ();
    }
	return gDefaultCacheName;
}

/*
 * Synchronize default cache for this process with system default cache
 */
 
static void
UpdateDefaultCache (void)
{
	cc_string_t 	name;
    cc_int32		cc_err = ccNoError;
	cc_context_t	cc_context = NULL;
    cc_int32		cc_version;
	
	cc_err = cc_initialize (&cc_context, ccapi_version_3, &cc_version, NULL);
    
    if (cc_err == ccNoError) {
        cc_err = cc_context_get_default_ccache_name (cc_context, &name);
	}
    
	if (cc_err == ccNoError) {
		krb_set_tkt_string ((char*) name -> data);
		cc_string_release (name);
	}
    
    if (cc_context != NULL)
        cc_context_release (cc_context);
}

/*
 * Setting name of default credentials cache
 */
void
krb_set_tkt_string (
	const char*			val)
{
	/* If we get called with the return value of tkt_string, we
	   shouldn't dispose of the input string */
	if (val != gDefaultCacheName) {
		if (gDefaultCacheName != NULL)
			free (gDefaultCacheName);
			
		gDefaultCacheName = malloc (strlen (val) + 1);
		if (gDefaultCacheName != NULL)
			strcpy (gDefaultCacheName, val);
	}
}

/*
 * Destroy credentials file
 *
 * Implementation in dest_tkt.c
 */
int KRB5_CALLCONV
dest_tkt (void)
{
	cc_int32		cc_err = ccNoError;
	cc_context_t	cc_context = NULL;
    cc_int32		cc_version;
    cc_ccache_t		ccache = NULL;
	
	cc_err = cc_initialize (&cc_context, ccapi_version_3, &cc_version, NULL);

    if (cc_err == ccNoError) {
        cc_err = cc_context_open_ccache (cc_context, TKT_FILE, &ccache);
	}
    
	if (cc_err == ccNoError) {
        cc_ccache_destroy (ccache);
	}
    
    if (ccache != NULL)
        cc_ccache_release (ccache);    
    if (cc_context != NULL)
        cc_context_release (cc_context);
    
	if (cc_err != ccNoError)
		return RET_TKFIL;
    else
        return KSUCCESS;
}

/*
 * The following functions are not part of the standard Kerberos v4 API. 
 * They were created for Mac implementation, and used by admin tools 
 * such as CNS-Config.
 */
 
/*
 * Number of credentials in credentials cache
 */
int KRB5_CALLCONV
krb_get_num_cred (void)
{
	cc_credentials_t			theCreds = NULL;
	int							count = 0;
	cc_credentials_iterator_t	iterator = NULL;
    cc_int32					cc_err = ccNoError;
	cc_context_t				cc_context = NULL;
    cc_int32					cc_version;
    cc_ccache_t					ccache = NULL;
    
	cc_err = cc_initialize (&cc_context, ccapi_version_3, &cc_version, NULL);

    if (cc_err == ccNoError) {
        cc_err = cc_context_open_ccache (cc_context, TKT_FILE, &ccache);
	}
		
    if (cc_err == ccNoError) {
        cc_err = cc_ccache_new_credentials_iterator (ccache, &iterator);
	}
	
    if (cc_err == ccNoError) {
        for (;;) {
            /* get next creds */
            cc_err = cc_credentials_iterator_next (iterator, &theCreds);
            if (cc_err != ccNoError)
                break;
    
            if (theCreds -> data -> version == cc_credentials_v4) 
                count++;
                
            cc_credentials_release (theCreds);
        }
    }
    
    if (iterator != NULL)
        cc_credentials_iterator_release (iterator);
    if (ccache != NULL)
        cc_ccache_release (ccache);    
    if (cc_context != NULL)
        cc_context_release (cc_context);
    
	if (cc_err != ccNoError)
		return 0;
    else
        return count;
}

/*
 * Retrieval from credentials file
 * This function is _not_!! well-defined under CCache API, because
 * there is no guarantee about order of credentials remaining the same.
 */
int KRB5_CALLCONV
krb_get_nth_cred (
	char*			sname,
	char*			sinstance,
	char*			srealm,
	int				n)
{
	cc_credentials_t 			theCreds = NULL;
	int							count = 0;
	cc_credentials_iterator_t	iterator = NULL;
    cc_int32					cc_err = ccNoError;
	cc_context_t				cc_context = NULL;
    cc_int32					cc_version;
    cc_ccache_t					ccache = NULL;
	
	if (n < 1)
		return KFAILURE;

	cc_err = cc_initialize (&cc_context, ccapi_version_3, &cc_version, NULL);
		
    if (cc_err == ccNoError) {
        cc_err = cc_context_open_ccache (cc_context, TKT_FILE, &ccache);
	}
		
    if (cc_err == ccNoError) {   
        cc_err = cc_ccache_new_credentials_iterator (ccache, &iterator);
	}
	
    if (cc_err == ccNoError) {
        for (count = 0; count < n;) {
            /* get next creds */
            cc_err = cc_credentials_iterator_next (iterator, &theCreds);
            if (cc_err != ccNoError)
                break;
    
            if (theCreds -> data -> version == cc_credentials_v4) 
                count++;
            
            if (count < n - 1)	
                cc_credentials_release (theCreds);
        }
    }
    
    if (cc_err == ccNoError) {
        strcpy (sname, theCreds -> data -> credentials.credentials_v4 -> service);
        strcpy (sinstance, theCreds -> data -> credentials.credentials_v4 -> service_instance);
        strcpy (srealm, theCreds -> data -> credentials.credentials_v4 -> realm);
	}
    
    if (theCreds != NULL)
        cc_credentials_release (theCreds);
    if (iterator != NULL)
        cc_credentials_iterator_release (iterator);
    if (ccache != NULL)
        cc_ccache_release (ccache);    
    if (cc_context != NULL)
        cc_context_release (cc_context);
    
	if (cc_err != ccNoError)
		return KFAILURE;
    else
        return KSUCCESS;
}

/*
 * Deletion from credentials file
 */
int KRB5_CALLCONV
krb_delete_cred (
	char*	sname,
	char*	sinstance,
	char*	srealm)
{
	cc_credentials_t			theCreds = NULL;
	cc_credentials_iterator_t	iterator = NULL;
    cc_int32					cc_err = ccNoError;
	cc_context_t				cc_context = NULL;
    cc_int32					cc_version;
    cc_ccache_t					ccache = NULL;
	
	cc_err = cc_initialize (&cc_context, ccapi_version_3, &cc_version, NULL);

	if (cc_err == ccNoError) {
        cc_err = cc_context_open_ccache (cc_context, TKT_FILE, &ccache);
	}
		
	if (cc_err == ccNoError) {
        cc_err = cc_ccache_new_credentials_iterator (ccache, &iterator);
	}
	
	if (cc_err == ccNoError) {
        for (;;) {
            /* get next creds */
            cc_err = cc_credentials_iterator_next (iterator, &theCreds);
            if (cc_err != ccNoError) {
                break;
            }
    
            if ((theCreds -> data -> version == cc_credentials_v4) &&
                (strcmp (theCreds -> data -> credentials.credentials_v4 -> service, sname) == 0) &&
                (strcmp (theCreds -> data -> credentials.credentials_v4 -> service_instance, sinstance) == 0) &&
                (strcmp (theCreds -> data -> credentials.credentials_v4 -> realm, srealm) == 0)) {
                
                cc_ccache_remove_credentials (ccache, theCreds);
                cc_credentials_release (theCreds);
                break;
            }
            
            cc_credentials_release (theCreds);
        }
    }
    
    if (iterator != NULL)
        cc_credentials_iterator_release (iterator);
    if (ccache != NULL)
        cc_ccache_release (ccache);    
    if (cc_context != NULL)
        cc_context_release (cc_context);
    
	if (cc_err != ccNoError)
		return KFAILURE;
    else
        return KSUCCESS;    
}

/*
 * Destroy all credential caches
 *
 * Implementation in memcache.c
 */
int KRB5_CALLCONV
dest_all_tkts (void)
{
	int						count = 0;
	cc_ccache_iterator_t	iterator = NULL;
    cc_int32				cc_err = ccNoError;
	cc_context_t			cc_context = NULL;
    cc_int32				cc_version;
    cc_ccache_t				ccache = NULL;
	
	cc_err = cc_initialize (&cc_context, ccapi_version_3, &cc_version, NULL);
    
    if (cc_err == ccNoError) {
        cc_err = cc_context_new_ccache_iterator (cc_context, &iterator);
	}
    
    if (cc_err == ccNoError) {
        for (;;) {
            /* get next ccache */
            cc_err = cc_ccache_iterator_next (iterator, &ccache);
            
            if (cc_err != ccNoError)
                break;
            
            cc_ccache_destroy (ccache);
            count++;
        }	
    }
    
    if (iterator != NULL)
        cc_credentials_iterator_release (iterator);
    if (cc_context != NULL)
        cc_context_release (cc_context);
    
    if ((cc_err == ccIteratorEnd) && (count == 0)) {
        /* first time, nothing to destroy */
        return KFAILURE;
    } else {
        if (cc_err == ccIteratorEnd) {
             /* done */
            return KSUCCESS;
        } else {
            /* error */
            return KFAILURE;
        }
    }
}
