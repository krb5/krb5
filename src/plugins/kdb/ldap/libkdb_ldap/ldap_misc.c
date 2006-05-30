/*
 * lib/kdb/kdb_ldap/ldap_misc.c
 *
 * Copyright (c) 2004-2005, Novell, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *   * The copyright holder's name is not used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <string.h>
#include <time.h>
#include "kdb_ldap.h"
#include "ldap_misc.h"
#include "ldap_err.h"

/*
 * This function reads the parameters from the krb5.conf file. The parameters read here are
 * DAL-LDAP specific attributes. Some of these are ldap_port, ldap_server ....
 *
 */
krb5_error_code
krb5_ldap_read_server_params(context, conf_section, srv_type)
     krb5_context               context;
     char                       *conf_section;
     int                        srv_type;
{
    char                        *tempval=NULL, *save_ptr=NULL;
    const char                  *delims="\t\n\f\v\r ,"; 
    krb5_error_code             st=0;
    kdb5_dal_handle             *dal_handle=NULL;
    krb5_ldap_context           *ldap_context=NULL;
    krb5_ldap_server_info       ***server_info=NULL;

    dal_handle = (kdb5_dal_handle *) context->db_context;
    ldap_context = (krb5_ldap_context *) dal_handle->db_context;

    /* copy the conf_section into ldap_context for later use */
    if (conf_section) {
      ldap_context->conf_section = strdup (conf_section);
      if (ldap_context->conf_section == NULL) {
	st = ENOMEM;
	goto cleanup;
      }
    }

    /* initialize the mutexs and condition variable */
    /* this portion logically doesn't fit here should be moved appropriately */
    
    /* this mutex is used in ldap reconnection pool */
    if (k5_mutex_init(&(ldap_context->hndl_lock)) != 0) {
	st = KRB5_KDB_SERVER_INTERNAL_ERR;
//	st = -1;
//	krb5_ldap_dal_err_funcp(context, krb5_err_have_str, st,
//				"k5_mutex_init failed");
	goto cleanup;
    }

    /* if max_server_conns is not set read it from database module section of conf file
     * this parameter defines maximum ldap connections per ldap server
     */
    if (ldap_context->max_server_conns == 0) {
	if ((st=profile_get_integer(context->profile, KDB_MODULE_SECTION, conf_section, 
				    "ldap_conns_per_server", 0, 
				    (int *) &ldap_context->max_server_conns)) != 0) {
            krb5_set_error_message (context, st, "Error reading 'ldap_conns_per_server' "
                    "attribute");
	    goto cleanup;
	}
    }
    
    /* if ldap port is not set read it from database module section of conf file */
    if (ldap_context->port == 0) {
	if ((st=profile_get_integer(context->profile, KDB_MODULE_SECTION, conf_section, 
				    "ldap_ssl_port", 0, 
				    (int *) &ldap_context->port)) != 0) {
            krb5_set_error_message (context, st, "Error reading 'ldap_ssl_port' attribute");
	    goto cleanup;
	}
    }
    
    /* if the bind dn is not set read it from the database module section of conf file 
     * this paramter is populated by one of the KDC, ADMIN or PASSWD dn to be used to connect 
     * to LDAP server. the srv_type decides which dn to read.
     */
    if( ldap_context->bind_dn == NULL ) {
	
	if (srv_type == KRB5_KDB_SRV_TYPE_KDC) {
	    if ((st=profile_get_string(context->profile, KDB_MODULE_SECTION, conf_section, 
				       "ldap_kdc_dn", NULL, &ldap_context->bind_dn)) != 0) {
                krb5_set_error_message (context, st, "Error reading 'ldap_kdc_dn' attribute");
		goto cleanup;
	    }
	}
	else if (srv_type == KRB5_KDB_SRV_TYPE_ADMIN) {
	    if ((st=profile_get_string(context->profile, KDB_MODULE_SECTION, conf_section, 
				       "ldap_kadmind_dn", NULL, &ldap_context->bind_dn)) != 0) {
                krb5_set_error_message (context, st, "Error reading 'ldap_kadmind_dn' attribute");
		goto cleanup;
	    }
	}
	else if (srv_type == KRB5_KDB_SRV_TYPE_PASSWD) {
	    if ((st=profile_get_string(context->profile, KDB_MODULE_SECTION, conf_section, 
				       "ldap_kpasswdd_dn", NULL, &ldap_context->bind_dn)) != 0) {
                krb5_set_error_message (context, st, "Error reading 'ldap_kpasswdd_dn' attribute");
		goto cleanup;
	    }
	}
    }

    /* read service_password_file parameter from database module section of conf file
     * this file contains stashed passwords of the KDC, ADMIN and PASSWD dns. 
     */
    if (ldap_context->service_password_file == NULL) {
	if ((st=profile_get_string(context->profile, KDB_MODULE_SECTION, conf_section, 
				   "ldap_service_password_file", NULL, 
				   &ldap_context->service_password_file)) != 0) {
            krb5_set_error_message (context, st, "Error reading 'ldap_service_password_file' attribute");
	    goto cleanup;
	}
    }
      
    /* if root certificate file is not set read it from database module section of conf file
     * this is the trusted root certificate of the Directory.
     */ 
    if (ldap_context->root_certificate_file == NULL) {
	if ((st=profile_get_string(context->profile, KDB_MODULE_SECTION, conf_section, 
				   "ldap_root_certificate_file", NULL, 
				   &ldap_context->root_certificate_file)) != 0) {
            krb5_set_error_message (context, st, "Error reading 'ldap_root_certificate_file' attribute");
	    goto cleanup;
	}
    }
      
    /* if the ldap server parameter is not set read the list of ldap servers:port from the 
     * database module section of the conf file 
     */
    
    if (ldap_context->server_info_list == NULL) {
	unsigned int ele=0;
	
	server_info = &(ldap_context->server_info_list);
	*server_info = (krb5_ldap_server_info **) calloc (SERV_COUNT+1, 
							  sizeof (krb5_ldap_server_info *));
	
	if (*server_info == NULL) {
	    st = ENOMEM;
	    goto cleanup;
	}
	
	if ((st=profile_get_string(context->profile, KDB_MODULE_SECTION, conf_section, 
				   "ldap_servers", NULL, &tempval)) != 0) {
            krb5_set_error_message (context, st, "Error reading 'ldap_servers' attribute");
	    goto cleanup;
	}
	
	if (tempval == NULL) {
	    
	    (*server_info)[ele] = (krb5_ldap_server_info *)calloc(1, 
								  sizeof(krb5_ldap_server_info));
	    
	    (*server_info)[ele]->server_name = strdup("localhost");
	    if ((*server_info)[ele]->server_name == NULL) {
		st = ENOMEM;
		goto cleanup;
	    }
	    (*server_info)[ele]->server_status = NOTSET;
	} else {
	    char *port=NULL, *server=NULL, *item=NULL;
	    
	    item = strtok_r(tempval,delims,&save_ptr);
	    while(item != NULL && ele<SERV_COUNT){
		(*server_info)[ele] = (krb5_ldap_server_info *)calloc(1, 
								      sizeof(krb5_ldap_server_info));
		if ((*server_info)[ele] == NULL) {
		    st = ENOMEM;
		    goto cleanup;
		}
		server=strtok_r(item, ":", &port);

		(*server_info)[ele]->server_name = strdup(server);
		if ((*server_info)[ele]->server_name == NULL) {
		    st = ENOMEM;
		    goto cleanup;
		}

		if (port) {
		    (*server_info)[ele]->port = atoi(port);
		}
		(*server_info)[ele]->server_status = NOTSET;
		item = strtok_r(NULL,delims,&save_ptr);
		++ele;
	    }
	    profile_release_string(tempval);
	}
    }

    /* the same set of all the above parameters can be obtained from the dbdefaults section of 
     * conf file. Here read the missing parameters from [dbdefaults] section */

    if (ldap_context->max_server_conns == 0) {
	if ((st=profile_get_integer(context->profile, KDB_MODULE_DEF_SECTION, 
				    "ldap_conns_per_server", NULL, DEFAULT_CONNS_PER_SERVER, 
				    (int *) &ldap_context->max_server_conns)) != 0) {
            krb5_set_error_message (context, st, "Error reading 'ldap_conns_per_server' attribute");
	    goto cleanup;
	}
    }

    if (ldap_context->max_server_conns < 2) {
	st = EINVAL;
	krb5_set_error_message (context, st, "Minimum connections required per server is 2");
	goto cleanup;
    }
    
    if (ldap_context->port == 0) {
	if ((st=profile_get_integer(context->profile, KDB_MODULE_DEF_SECTION, "ldap_ssl_port", 
				    NULL, LDAPS_PORT, &ldap_context->port)) != 0) {
            krb5_set_error_message (context, st, "Error reading 'ldap_ssl_port' attribute");
	    goto cleanup;
	}
    }

    if( ldap_context->bind_dn == NULL ) {
	if (srv_type == KRB5_KDB_SRV_TYPE_KDC) {
	    if ((st=profile_get_string(context->profile, KDB_MODULE_DEF_SECTION, "ldap_kdc_dn", 
				       NULL, NULL, &ldap_context->bind_dn)) != 0) {
                krb5_set_error_message (context, st, "Error reading 'ldap_kdc_dn' attribute");
		goto cleanup;
	    }
	}
	else if (srv_type == KRB5_KDB_SRV_TYPE_ADMIN) {
	    if ((st=profile_get_string(context->profile, KDB_MODULE_DEF_SECTION, 
				       "ldap_kadmind_dn", NULL, NULL, 
				       &ldap_context->bind_dn)) != 0) {
                krb5_set_error_message (context, st, "Error reading 'ldap_kadmind_dn' attribute");
		goto cleanup;
	    }
	}
	else if (srv_type == KRB5_KDB_SRV_TYPE_PASSWD) {
	    if ((st=profile_get_string(context->profile, KDB_MODULE_DEF_SECTION, 
				       "ldap_kpasswdd_dn", NULL, NULL, 
				       &ldap_context->bind_dn)) != 0) {
                krb5_set_error_message (context, st, "Error reading 'ldap_kpasswdd_dn' attribute");
		goto cleanup;
	    }
	}
    }

    /* read service_password_file value */
    if (ldap_context->service_password_file == NULL) {
	if ((st=profile_get_string(context->profile, KDB_MODULE_DEF_SECTION, 
				   "ldap_service_password_file", NULL, NULL, 
				   &ldap_context->service_password_file)) != 0) {
            krb5_set_error_message (context, st, "Error reading 'ldap_service_passwd_file' attribute");
	    goto cleanup;
	}
    }
    
    /* read root certificate file value */
    if (ldap_context->root_certificate_file == NULL) {
	if ((st=profile_get_string(context->profile, KDB_MODULE_DEF_SECTION, 
				   "ldap_root_certificate_file", NULL, NULL, 
				   &ldap_context->root_certificate_file)) != 0) {
            krb5_set_error_message (context, st, "Error reading 'ldap_root_certificate_file' attribute");
	    goto cleanup;
	}
    }
    
 cleanup:
    return(st);
}

/*
 * This function frees the krb5_ldap_context structure members.
 */

krb5_error_code
krb5_ldap_free_server_params(ldap_context)
    krb5_ldap_context           *ldap_context;
{
    int                         i=0;
    krb5_ldap_server_handle     *ldap_server_handle=NULL, *next_ldap_server_handle=NULL;

    if (ldap_context == NULL)
	return 0;
    
    /* free all ldap servers list and the ldap handles associated with the ldap server */
    if(ldap_context->server_info_list) {
	while (ldap_context->server_info_list[i]) {
	    if (ldap_context->server_info_list[i]->server_name) {
		free (ldap_context->server_info_list[i]->server_name);
	    }
	    if (ldap_context->server_info_list[i]->root_certificate_file) {
		free (ldap_context->server_info_list[i]->root_certificate_file);
	    }
	    if (ldap_context->server_info_list[i]->ldap_server_handles) {
		ldap_server_handle = ldap_context->server_info_list[i]->ldap_server_handles;
		while (ldap_server_handle) {
		    ldap_unbind_s(ldap_server_handle->ldap_handle);
		    ldap_server_handle->ldap_handle = NULL;
		    next_ldap_server_handle = ldap_server_handle->next;
		    krb5_xfree(ldap_server_handle);
		    ldap_server_handle = next_ldap_server_handle;
		}
	    }
	    krb5_xfree(ldap_context->server_info_list[i]);
	    i++;
	}
	krb5_xfree(ldap_context->server_info_list);
    }
      
    if (ldap_context->conf_section != NULL) {
	krb5_xfree(ldap_context->conf_section);
	ldap_context->conf_section = NULL;
    }

    if (ldap_context->bind_dn != NULL) {
	krb5_xfree(ldap_context->bind_dn);
	ldap_context->bind_dn = NULL;
    }

    if (ldap_context->bind_pwd != NULL) {
	krb5_xfree(ldap_context->bind_pwd);
	ldap_context->bind_pwd = NULL;
    }

    if (ldap_context->service_password_file != NULL) {
	krb5_xfree(ldap_context->service_password_file);
	ldap_context->service_password_file = NULL;
    }

    if (ldap_context->root_certificate_file != NULL) {
	krb5_xfree(ldap_context->root_certificate_file);
	ldap_context->root_certificate_file = NULL;
    }

    if (ldap_context->service_cert_path != NULL) {
	krb5_xfree(ldap_context->service_cert_path);
	ldap_context->service_cert_path = NULL;
    }

    if (ldap_context->service_cert_pass != NULL) {
	krb5_xfree(ldap_context->service_cert_pass);
	ldap_context->service_cert_pass = NULL;
    }

    if (ldap_context->certificates) {
	i=0;
	while (ldap_context->certificates[i] != NULL) {
	    krb5_xfree(ldap_context->certificates[i]->certificate);
	    krb5_xfree(ldap_context->certificates[i]);
	    ++i;
	}
	krb5_xfree(ldap_context->certificates);
    }

    k5_mutex_destroy(&ldap_context->hndl_lock);

    krb5_xfree(ldap_context);
    return(0);
}


/*
 * check to see if the principal belongs to the default realm.
 * The default realm is present in the krb5_ldap_context structure.
 * The principal has a realm portion. This realm portion is compared with the default realm
 * to check whether the principal belong to the default realm.
 * Return 0 if principal belongs to default realm else 1.
 */

krb5_error_code
is_principal_in_realm(ldap_context, searchfor)
     krb5_ldap_context          *ldap_context;
     krb5_const_principal       searchfor;
{
    int                         defrealmlen=0;
    char                        *defrealm=NULL;
  
#define FIND_MAX(a,b) ((a) > (b) ? (a) : (b))

    defrealmlen = strlen(ldap_context->lrparams->realm_name);
    defrealm = ldap_context->lrparams->realm_name;
  
    /* care should be taken for inter-realm principals as the default realm can exist in the
     * realm part of the principal name or can also exist in the second portion of the name part. 
     * However, if the default realm exist in the second part of the principal portion, then the 
     * first portion of the principal name SHOULD be "krbtgt". All this check is done in the 
     * immediate block.
     */
    if (searchfor->length == 2) 
	if ((strncasecmp(searchfor->data[0].data, "krbtgt", 
			 FIND_MAX(searchfor->data[0].length, strlen("krbtgt"))) == 0) && 
	    (strncasecmp(searchfor->data[1].data, defrealm, 
			 FIND_MAX(searchfor->data[1].length, defrealmlen)) == 0)) 
	    return 0;
  
    /* first check the length, if they are not equal, then they are not same */
    if (strlen(defrealm) != searchfor->realm.length)
	return 1;
  
    /* if the length is equal, check for the contents */
    if (strncmp(defrealm, searchfor->realm.data, 
		searchfor->realm.length) != 0)
	return 1;
    /* if we are here, then the realm portions match, return 0 */
    return 0;
}


/*
 * Deduce the subtree information from the context. A realm can have atmost 2 subtrees. 
 * 1. the Realm container 
 * 2. the actual subtree associated with the Realm
 *
 * However, there are some conditions to be considered to deduce the actual subtree/s associated
 * with the realm. The conditions are as follows
 * 1. If the subtree information of the Realm is [Root] or NULL (that is internal a [Root]) then
 *    the realm has only one subtree i.e [Root], i.e. whole of the tree.
 * 2. If the subtree information of the Realm is missing/absent, then the realm has only one
 *    i.e. the Realm container. NOTE: In call cases Realm container SHOULD be the one among the
 *    subtrees or the only one subtree. 
 * 3. The subtree information of the realm is overlapping the realm container of the realm, then
 *    the realm has only one subtree and it is the subtree information associated with the realm.
 */
krb5_error_code
krb5_get_subtree_info(ldap_context, subtreearr, ntree)
    krb5_ldap_context           *ldap_context;
    char                        **subtreearr;
    unsigned int                *ntree;
{
    int                         lendiff=0;
    char                        *subtree=NULL, *realm_cont_dn=NULL;

    subtree = ldap_context->lrparams->subtree;
    realm_cont_dn = ldap_context->lrparams->realmdn;

    /* 
     * if subtree attribute value is [Root] of the tree which is represented by a "" 
     * (null) string, set the ntree value as 1 and do not fill the subtreearr value.
     * In eDirectory the [Root] can be represented as a "" (null) string, however this
     * representation throws a "No such object" error in OpenLDAP. 
     * Representing [Root] of the tree as NULL pointer (i.e. no value) works in both case.
     */
    if (subtree == NULL || strcasecmp(subtree, "") == 0) {
	*ntree = 1;
	return 0;
    }
	
    /* 
     * the subtree attribute value of the realm can be same as the realm container or can 
     * even overlap. If the check is successful, then the subtree attribute value alone is 
     * copied to the subtreearr array and the ntree value is set to 1.
     */
    lendiff = strlen(realm_cont_dn) - strlen(subtree);
    if (lendiff >= 0 && (strcasecmp(realm_cont_dn+lendiff, subtree)==0)) {
	subtreearr[0] = strdup(subtree);
	if (subtreearr[0] == NULL) 
	    return ENOMEM;
	*ntree = 1;
	return 0;
    } 
	
    /*
     * if the subtree attribute value of the realm and the realm container are different,
     * then both of the values are copied to subtreearr and ntree value is set to 2.
     */
    subtreearr[0] = strdup(realm_cont_dn);
    if (subtreearr[0] == NULL) 
	return ENOMEM;
    subtreearr[1] = strdup(subtree);
    if (subtreearr[1] == NULL) {
	if (subtreearr[0])
	    free (subtreearr[0]);
	return ENOMEM;
    }
    *ntree = 2;
    return 0;
}

/*
 * This function appends the content with a type into the tl_data structure. Based on the type
 * the length of the content is either pre-defined or computed from the content. 
 * Returns 0 in case of success and 1 if the type associated with the content is undefined.
 */

krb5_error_code
store_tl_data(tl_data, tl_type, value)
    krb5_tl_data                *tl_data;
    int                         tl_type;
    void                        *value;
{
    unsigned int                currlen=0, tldatalen=0;
    char                        *curr=NULL;
    void                        *reallocptr=NULL;
  
    tl_data->tl_data_type = KDB_TL_USER_INFO;
    switch(tl_type)
    {
    case KDB_TL_PRINCCOUNT:
    case KDB_TL_PRINCTYPE:
    case KDB_TL_MASK:
    {
    	int *iptr = (int *)value;
    	int ivalue = *iptr;
    	
    	currlen = tl_data->tl_data_length;
    	tl_data->tl_data_length += 1 + 2 + 2;
	/* allocate required memory */
    	reallocptr = tl_data->tl_data_contents;
    	tl_data->tl_data_contents = realloc(tl_data->tl_data_contents, 
    					    tl_data->tl_data_length);
    	if (tl_data->tl_data_contents == NULL) {
    	    if (reallocptr)
    		free (reallocptr);
    	    return ENOMEM;
    	}
    	curr = (char *) (tl_data->tl_data_contents + currlen);
    	
	/* store the tl_type value */
    	memset(curr, tl_type, 1);
    	curr += 1;
	/* store the content length */
    	tldatalen = 2;
    	STORE16_INT(curr, tldatalen);
    	curr += 2;
	/* store the content */
    	STORE16_INT(curr, ivalue);	
    	curr += 2;
	break;
    }

    case KDB_TL_USERDN:
    case KDB_TL_TKTPOLICYDN:
    {
    	char *cptr = (char *)value;
    	
    	currlen = tl_data->tl_data_length;
    	tl_data->tl_data_length += 1 + 2 + strlen(cptr);
	/* allocate required memory */	
    	reallocptr = tl_data->tl_data_contents;
    	tl_data->tl_data_contents = realloc(tl_data->tl_data_contents, 
    					    tl_data->tl_data_length);
    	if (tl_data->tl_data_contents == NULL) {
    	    if (reallocptr)
    		free (reallocptr);
    	    return ENOMEM;
    	}
    	curr = (char *) (tl_data->tl_data_contents + currlen);
    	
	/* store the tl_type value */
    	memset(curr, tl_type, 1);
    	curr += 1;
	/* store the content length */
    	tldatalen = strlen(cptr);
    	STORE16_INT(curr, tldatalen);
    	curr += 2;
	/* store the content */
    	memcpy(curr, cptr, tldatalen);
    	curr += tldatalen;
    	break;
    }

    case KDB_TL_KEYINFO:
    {
    	struct berval *key = (struct berval *)value;
    	
    	currlen = tl_data->tl_data_length;
    	tl_data->tl_data_length += 1 + 2 + key->bv_len;
	/* allocate required memory */
    	reallocptr = tl_data->tl_data_contents;
    	tl_data->tl_data_contents = realloc(tl_data->tl_data_contents, 
    					    tl_data->tl_data_length);
    	if (tl_data->tl_data_contents == NULL) {
    	    if (reallocptr)
    		free (reallocptr);
    	    return ENOMEM;
    	}
    	curr = (char *) (tl_data->tl_data_contents + currlen);
    	
	/* store the tl_type value */
    	memset(curr, tl_type, 1);
    	curr += 1;
	/* store the content length */
    	tldatalen = key->bv_len;
    	STORE16_INT(curr, tldatalen);
    	curr += 2;
	/* store the content */
    	memcpy(curr, key->bv_val, key->bv_len);
    	curr += tldatalen;
    	break;
    }
    
    default:
	return 1;
    
    }
    return 0;
}

/*
 * This function scans the tl_data structure to get the value of a type defined by the tl_type 
 * (second parameter). The tl_data structure has all the data in the tl_data_contents member. 
 * The format of the tl_data_contents is as follows.
 * The first byte defines the type of the content that follows. The next 2 bytes define the 
 * size n (in terms of bytes) of the content that follows. The next n bytes define the content
 * itself.
 */

krb5_error_code
decode_tl_data(tl_data, tl_type, data)
    krb5_tl_data                *tl_data;
    int                         tl_type;
    void                        **data;
{
    int                         subtype=0, i=0, limit=10;
    unsigned int                sublen=0;
    unsigned char               *curr=NULL;
    int                         *intptr=NULL;
    long                        *longptr=NULL;
    char                        *DN=NULL;  
    krb5_boolean                keyfound=FALSE;
    KEY                         *secretkey = NULL;

    *data = NULL;

    curr = tl_data->tl_data_contents;
    while(curr < (tl_data->tl_data_contents + tl_data->tl_data_length)) {

	/* get the type of the content */
	memset(&subtype, curr[0], 1);
	/* forward by 1 byte*/
	curr += 1;
    
	if (subtype == tl_type) {
	    switch(subtype) {

	    case KDB_TL_PRINCCOUNT:
	    case KDB_TL_PRINCTYPE:
	    case KDB_TL_MASK:
		/* get the length of the content */
		UNSTORE16_INT(curr, sublen);
		/* forward by 2 bytes */
		curr += 2;
		/* get the actual content */
		if (sublen == 2) {
		  /* intptr = malloc(sublen);	  */
		    intptr = malloc(sizeof(krb5_int32));
		    if (intptr == NULL) 
			return ENOMEM;
		    memset(intptr, 0, sublen);
		    UNSTORE16_INT(curr, (*intptr));
		    *data = intptr;
		} else { 
		    longptr = malloc(sublen);	  
		    if (longptr == NULL) 
			return ENOMEM;
		    memset(longptr, 0, sublen);
		    UNSTORE32_INT(curr, (*longptr));
		    *data = longptr;
		}
		curr += sublen;
		return 0;
		break;

	    case KDB_TL_CONTAINERDN:
	    case KDB_TL_USERDN:
	    case KDB_TL_TKTPOLICYDN:
		/* get the length of the content */
		UNSTORE16_INT(curr, sublen);
		/* forward by 2 bytes */
		curr += 2;
		DN = malloc (sublen + 1);
		if (DN == NULL)
		    return ENOMEM;
		memcpy(DN, curr, sublen);
		DN[sublen] = 0;
		*data = DN;
		curr += sublen;
		return 0;
		break;

	    case KDB_TL_KEYINFO:
		/* get the length of the content */
		keyfound = TRUE;
		UNSTORE16_INT(curr, sublen);
		/* forward by 2 bytes */
		curr += 2;
		if (secretkey == NULL) {
		    secretkey = malloc(sizeof(*secretkey));
		    if (secretkey == NULL)
			return ENOMEM;
		    secretkey->nkey = 0;
		    secretkey->keys = NULL;
		    secretkey->keys = realloc(secretkey->keys, 
					      sizeof(*(secretkey->keys)) * (limit));	  
		    if (secretkey->keys == NULL)
			return ENOMEM;
		    memset(secretkey->keys, 0, sizeof (*(secretkey->keys)) * (limit));
		}
		if ( i == limit-1) {
		    limit *= 2;
		    secretkey->keys = realloc(secretkey->keys, 
					      sizeof(*(secretkey->keys)) * (limit));
		    if (secretkey->keys == NULL)
                        return ENOMEM;
		    memset(secretkey->keys+i, 0, sizeof (*(secretkey->keys)) * (limit-i));
		}

		secretkey->keys[i] = malloc (sizeof(struct berval));
		if (secretkey->keys[i] == NULL)
		    return ENOMEM;

		secretkey->keys[i]->bv_len = sublen;
		secretkey->keys[i]->bv_val = malloc (sublen);
		if (secretkey->keys[i]->bv_val == NULL)
		    return ENOMEM;

		memcpy(secretkey->keys[i]->bv_val, curr, sublen);
		secretkey->nkey = ++i;
		*data = secretkey;
		curr += sublen;
		break;
	    }
	} else {
	    /* move to the current content block */
	    UNSTORE16_INT(curr, sublen);
	    curr += 2 + sublen;
	}
    }
    if (tl_type == KDB_TL_KEYINFO) {
	if (keyfound)
	    return 0;
	else 
	    return EINVAL;
    }
    return EINVAL;
}

/* 
 * wrapper routines for decode_tl_data
 */
static krb5_error_code
krb5_get_int_from_tl_data(context, entries, type, intval)
    krb5_context                context;
    krb5_db_entry               *entries;
    int                         type;
    int                         *intval;
{
    krb5_error_code             st=0;
    krb5_tl_data                tl_data;
    void                        *voidptr=NULL;
    int                         *intptr=NULL;
    
    tl_data.tl_data_type = KDB_TL_USER_INFO;
    if (((st=krb5_dbe_lookup_tl_data(context, entries, &tl_data)) != 0) || tl_data.tl_data_length == 0)
	goto cleanup;
    
    if (decode_tl_data(&tl_data, type, &voidptr) == 0) {
	intptr = (int *) voidptr;
	*intval = *intptr;
	free(intptr);
    }

 cleanup:
    return st;
}

/*
 * get the mask representing the attributes set on the directory object (user, policy ...) 
 */
krb5_error_code
krb5_get_attributes_mask(context, entries, mask)
    krb5_context                context;
    krb5_db_entry               *entries;
    int                         *mask;
{
    return krb5_get_int_from_tl_data(context, entries, KDB_TL_MASK, mask);
}

krb5_error_code
krb5_get_princ_type(context, entries, ptype)
    krb5_context                context;
    krb5_db_entry               *entries;
    int                         *ptype;
{
    return krb5_get_int_from_tl_data(context, entries, KDB_TL_PRINCTYPE, ptype);
}

krb5_error_code
krb5_get_princ_count(context, entries, pcount)
    krb5_context                context;
    krb5_db_entry               *entries;
    int                         *pcount;
{
    return krb5_get_int_from_tl_data(context, entries, KDB_TL_PRINCCOUNT, pcount);
}

krb5_error_code
krb5_get_secretkeys(context, entries, secretkey)
    krb5_context                context;
    krb5_db_entry               *entries;
    KEY                         **secretkey;
{
    krb5_error_code             st=0;
    krb5_tl_data                tl_data;
    void                        *voidptr=NULL;
    
    tl_data.tl_data_type = KDB_TL_USER_INFO;
    if (((st=krb5_dbe_lookup_tl_data(context, entries, &tl_data)) != 0) || tl_data.tl_data_length == 0)
	goto cleanup;
    
    if (decode_tl_data(&tl_data, KDB_TL_KEYINFO, &voidptr) == 0) {
	*secretkey = (KEY *) voidptr;
    }

 cleanup:
    return st;
}

static krb5_error_code
krb5_get_str_from_tl_data(context, entries, type, strval)
    krb5_context                context;
    krb5_db_entry               *entries;
    int                         type;
    char                        **strval;
{
    krb5_error_code             st=0;
    krb5_tl_data                tl_data;
    void                        *voidptr=NULL;
    
    if (type != KDB_TL_USERDN && type != KDB_TL_CONTAINERDN && type != KDB_TL_TKTPOLICYDN) {
	st = EINVAL;
	goto cleanup;
    }

    tl_data.tl_data_type = KDB_TL_USER_INFO;
    if (((st=krb5_dbe_lookup_tl_data(context, entries, &tl_data)) != 0) || tl_data.tl_data_length == 0)
	goto cleanup;
    
    if (decode_tl_data(&tl_data, type, &voidptr) == 0) {
	*strval = (char *) voidptr;
    }

 cleanup:
    return st;
}

krb5_error_code
krb5_get_userdn(context, entries, userdn)
    krb5_context                context;
    krb5_db_entry               *entries;
    char                        **userdn;
{
    *userdn = NULL;
    return krb5_get_str_from_tl_data(context, entries, KDB_TL_USERDN, userdn);
}

krb5_error_code
krb5_get_containerdn(context, entries, containerdn)
    krb5_context                context;
    krb5_db_entry               *entries;
    char                        **containerdn;
{
    *containerdn = NULL;
    return krb5_get_str_from_tl_data(context, entries, KDB_TL_CONTAINERDN, containerdn);
}

krb5_error_code
krb5_get_policydn(context, entries, policydn)
    krb5_context                context;
    krb5_db_entry               *entries;
    char                        **policydn;
{
    *policydn = NULL;
    return krb5_get_str_from_tl_data(context, entries, KDB_TL_TKTPOLICYDN, policydn);
}
/*
 * This function reads the attribute values (if the attribute is non-null) from the dn. 
 * The read attribute values is compared aganist the attrvalues passed to the function
 * and a bit mask is set for all the matching attributes (attributes existing in both list).
 * The bit to be set is selected such that the index of the attribute in the attrvalues 
 * parameter is the position of the bit.
 * For ex: the first element in the attrvalues is present in both list shall set the LSB of the
 * bit mask.
 *
 * In case if either the attribute or the attrvalues parameter to the function is NULL, then
 * the existence of the object is considered and appropriate status is returned back
 */

krb5_error_code
checkattributevalue (ld, dn, attribute, attrvalues, mask)
    LDAP                        *ld;
    char                        *dn;
    char                        *attribute;
    char                        **attrvalues;
    int                         *mask;
{
    int                         st=0, one=1;
    char                        **values=NULL, *attributes[2] = {NULL}; 
    LDAPMessage                 *result=NULL, *entry=NULL;
  
    if (strlen(dn) == 0)
      return LDAP_NO_SUCH_OBJECT;

    attributes[0] = attribute;

    /* read the attribute values from the dn */
    if((st = ldap_search_ext_s( ld,
				dn,
				LDAP_SCOPE_BASE,
				0,
				attributes,
				0,
				NULL,
				NULL,
				&timelimit,
				LDAP_NO_LIMIT,
				&result)) != LDAP_SUCCESS) {
        st = set_ldap_error(0, st, OP_SEARCH);
	return st;
    }
  
    /* 
     * If the attribute/attrvalues is NULL, then check for the existence of the object alone
     */
    if (attribute == NULL || attrvalues == NULL)
	goto cleanup;

    /* reset the bit mask */
    *mask = 0;

    if((entry=ldap_first_entry(ld, result)) != NULL) {
	/* read the attribute values */
	if((values=ldap_get_values(ld, entry, attribute)) != NULL) {
	    int i,j;
	    
	    /* compare the read attribute values with the attrvalues array and set the 
	     * appropriate bit mask 
	     */
    	    for(j=0; attrvalues[j]; ++j) {
    		for(i=0; values[i]; ++i) {
		    if(strcasecmp(values[i], attrvalues[j]) == 0) {
			*mask |= (one<<j);
			break;
		    }
		}
	    }
	    ldap_value_free(values);
	}
    }
    
 cleanup:
    ldap_msgfree(result);
    return st;
}


/*
 * This function updates a single attribute with a single value of a specified dn. 
 * This function is mainly used to update krbRealmReferences, krbKdcServers, krbAdminServers...
 * when KDC, ADMIN, PASSWD servers are associated with some realms or vice versa.
 */

krb5_error_code 
updateAttribute (ld, dn, attribute, value)
    LDAP                        *ld;
    char                        *dn;
    char                        *attribute;
    char                        *value;
{
    int                         st=0;
    LDAPMod                     modAttr, *mods[2]={NULL};
    char                        *values[2]={NULL}; 

    values[0] = value;

    /* data to update the {attr,attrval} combination */
    memset(&modAttr, 0, sizeof(modAttr));
    modAttr.mod_type = attribute;
    modAttr.mod_op = LDAP_MOD_ADD;
    modAttr.mod_values = values;
    mods[0] = &modAttr;
  
    /* ldap modify operation */
    st = ldap_modify_s(ld, dn, mods);

    /* if the {attr,attrval} combination is already present return a success 
     * LDAP_ALREADY_EXISTS is for single-valued attribute
     * LDAP_TYPE_OR_VALUE_EXISTS is for multi-valued attribute
     */
    if (st == LDAP_ALREADY_EXISTS || st == LDAP_TYPE_OR_VALUE_EXISTS)
	st = 0;

    if (st != 0) {
        st = set_ldap_error (0, st, OP_MOD);
    }
    
    return st;
}
   
/*
 * This function deletes a single attribute with a single value of a specified dn. 
 * This function is mainly used to delete krbRealmReferences, krbKdcServers, krbAdminServers...
 * when KDC, ADMIN, PASSWD servers are disassociated with some realms or vice versa.
 */

krb5_error_code 
deleteAttribute (ld, dn, attribute, value)
    LDAP                        *ld;
    char                        *dn;
    char                        *attribute;
    char                        *value;
{
    krb5_error_code             st=0;
    LDAPMod                     modAttr, *mods[2]={NULL};
    char                        *values[2]={NULL}; 

    values[0] = value;

    /* data to delete the {attr,attrval} combination */
    memset(&modAttr, 0, sizeof(modAttr));
    modAttr.mod_type = attribute;
    modAttr.mod_op = LDAP_MOD_DELETE;
    modAttr.mod_values = values;
    mods[0] = &modAttr;
  
    /* ldap modify operation */
    st = ldap_modify_s(ld, dn, mods);
    
    /* if either the attribute or the attribute value is missing return a success */
    if (st == LDAP_NO_SUCH_ATTRIBUTE || st == LDAP_UNDEFINED_TYPE)
	st = 0;
   
    if (st != 0) {
	st = set_ldap_error (0, st, OP_MOD);
    }
    
    return st;
}


/*
 * This function takes in 2 string arrays, compares them to remove the matching entries. 
 * The first array is the original list and the second array is the modified list. Removing
 * the matching entries will result in a reduced array, where the left over first array elements
 * are the deleted entries and the left over second array elements are the added entries.
 * These additions and deletions has resulted in the modified second array.
 */

krb5_error_code
disjoint_members(src, dest)
    char                        **src;
    char                        **dest;
{
    int                         i=0, j=0, slen=0, dlen=0;

    /* validate the input parameters */
    if (src == NULL || dest == NULL)
	return 0;
    
    /* compute the first array length */
    for (i=0;src[i]; ++i) 
	;
    
    /* return if the length is 0 */
    if (i==0)  
	return 0;

    /* index of the last element and also the length of the array */
    slen = i-1;

    /* compute the second array length */
    for (i=0;dest[i]; ++i) 
	;

    /* return if the length is 0 */
    if (i==0)
	return 0;
  
    /* index of the last element and also the length of the array */
    dlen = i-1;
  
    /* check for the similar elements and delete them from both the arrays */
    for(i=0; src[i]; ++i) {

	for(j=0; dest[j]; ++j) {

	    /* if the element are same */
	    if (strcasecmp(src[i], dest[j]) == 0) {
		/* if the matched element is in the middle, then copy the last element to
		 * the matched index.
		 */
		if (i != slen) {
		    free (src[i]);
		    src[i] = src[slen];
		    src[slen] = NULL;
		} else {
		    /* if the matched element is the last, free it and set it to NULL */
		    free (src[i]);
		    src[i] = NULL;
		}
		/* reduce the array length by 1 */
		slen -= 1;
	
		/* repeat the same processing for the second array too */
		if (j != dlen) {
		    free(dest[j]);
		    dest[j] = dest[dlen];
		    dest[dlen] = NULL;
		} else { 
		    free(dest[j]);
		    dest[j] = NULL;
		}
		dlen -=1;

		/* the source array is reduced by 1, so reduce the index variable used for 
		 * source array by 1. No need to adjust the second array index variable as
		 * it is reset while entering the inner loop
		 */
		i -= 1;
		break;
	    }
	}
    }
    return 0;
}

/*
 * This function replicates the contents of the src array for later use. Mostly the contents
 * of the src array is obtained from a ldap_search operation and the contents are required
 * for later use.
 */

krb5_error_code 
copy_arrays(src, dest, count)
    char                        **src;
    char                        ***dest;
    int                         count;
{
    krb5_error_code             st=0;
    int                         i=0;

    /* validate the input parameters */
    if (src == NULL || dest == NULL)
      return 0;
    
    /* allocate memory for the dest array */
    *dest = (char **) calloc((unsigned) count+1, sizeof(char *));
    if (*dest == NULL) {
	st = ENOMEM;
	goto cleanup;
    }

    /* copy the members from src to dest array. */
    for (i=0; i < count && src[i] != NULL; ++i) {
	(*dest)[i] = strdup(src[i]);
	if ((*dest)[i] == NULL) {
	    st = ENOMEM;
	    goto cleanup;
	}
    }

 cleanup:
    /* in case of error free up everything and return */
    if (st != 0) {
	if (*dest != NULL) {
	    for(i=0; (*dest)[i]; ++i) {
		free ((*dest)[i]);
		(*dest)[i] = NULL;
	    }
	    free (*dest);
	    *dest = NULL;
	}
    }
    return st;
}

static krb5_error_code
getepochtime(strtime, epochtime)
    char              *strtime;
    krb5_timestamp    *epochtime;
{
    struct tm           tme;

    memset(&tme, 0, sizeof(tme));
    if (strptime(strtime,"%Y%m%d%H%M%SZ", &tme) == NULL) {
	*epochtime = 0;
	return EINVAL;
    }
    *epochtime = krb5int_gmt_mktime(&tme);
    return 0;
}

/*
 * krb5_ldap_get_value() - get the integer value of the attribute
 * Returns, 0 if the attribute is present, 1 if the attribute is missing.
 * The retval is 0 if the attribute is missing.
 */

krb5_error_code 
krb5_ldap_get_value(ld, ent, attribute, retval)
    LDAP                        *ld;
    LDAPMessage                 *ent;
    char                        *attribute;
    int                         *retval;
{
    char                           **values=NULL;

    *retval = 0;
    values=ldap_get_values(ld, ent, attribute);
    if (values != NULL) {
	if (values[0] != NULL)
	    *retval = atoi(values[0]);
	ldap_value_free(values);
	return 0;
    }
    return 1;
}

/*
 * krb5_ldap_get_string() - Returns the first string of the attribute. Intended to 
 *
 *
 */
krb5_error_code 
krb5_ldap_get_string(ld, ent, attribute, retstr, attr_present)
    LDAP                        *ld;
    LDAPMessage                 *ent;
    char                        *attribute;
    char                        **retstr;
    krb5_boolean                *attr_present;
{
    char                           **values=NULL;
    krb5_error_code                st=0;

    *retstr = NULL;
    if (attr_present != NULL)
      *attr_present = FALSE;

    values=ldap_get_values(ld, ent, attribute);
    if (values != NULL) {
	if (values[0] != NULL) {
	    if (attr_present!= NULL)
		*attr_present = TRUE;
	    *retstr = strdup(values[0]);
	    if (*retstr == NULL)
		st = ENOMEM;
	}
	ldap_value_free(values);
    }
    return st;
}

krb5_error_code 
krb5_ldap_get_time(ld, ent, attribute, rettime, attr_present)
    LDAP                        *ld;
    LDAPMessage                 *ent;
    char                        *attribute;
    krb5_timestamp              *rettime;
    krb5_boolean                *attr_present;
{
    char                         **values=NULL;
    krb5_error_code              st=0;

    *rettime = 0;
    *attr_present = FALSE;

    values=ldap_get_values(ld, ent, attribute);
    if (values != NULL) {
	if (values[0] != NULL) {
	    *attr_present = TRUE;
	    st = getepochtime(values[0], rettime);
	}
	ldap_value_free(values);
    }
    return st;
}

/*
 * Function to allocate, set the values of LDAPMod structure. The LDAPMod structure is then
 * added to the array at the ind 
 */

krb5_error_code 
krb5_add_member(mods, count)
     LDAPMod          ***mods;
     int              *count;
{
    int i=0;
    LDAPMod **lmods=NULL;
    
    if ((*mods) != NULL) {
      for (;(*mods)[i] != NULL; ++i)
	;
    }  
    lmods = (LDAPMod **) realloc((*mods), (2+i) * sizeof(LDAPMod *));
    if (lmods == NULL)
      return ENOMEM;

    *mods = lmods;
    (*mods)[i+1] = NULL;
    (*mods)[i] = (LDAPMod *) calloc(1, sizeof (LDAPMod));
    if ((*mods)[i] == NULL)
	return ENOMEM;
    *count = i;
    return 0;
}

krb5_error_code
krb5_add_str_mem_ldap_mod(mods, attribute, op, values) 
     LDAPMod  ***mods;
     char     *attribute;
     int      op;
     char     **values;

{
    int i=0, j=0;
    krb5_error_code   st=0;

    if ((st=krb5_add_member(mods, &i)) != 0)
      return st;
    
    (*mods)[i]->mod_type = strdup(attribute);
    if ((*mods)[i]->mod_type == NULL)
      return ENOMEM;
    (*mods)[i]->mod_op = op;

    if (values != NULL) {
      for (j=0; values[j] != NULL; ++j)
	;
      (*mods)[i]->mod_values = malloc (sizeof(char *) * (j+1));  
      if ((*mods)[i]->mod_values == NULL)
	  return ENOMEM;
      
      for (j=0; values[j] != NULL; ++j) {
	(*mods)[i]->mod_values[j] = strdup(values[j]);      
	if ((*mods)[i]->mod_values[j] == NULL)
	    return ENOMEM;
      }
      (*mods)[i]->mod_values[j] = NULL;
    }
    return 0;
}

krb5_error_code
krb5_add_ber_mem_ldap_mod(mods, attribute, op, ber_values) 
     LDAPMod  ***mods;
     char     *attribute;
     int      op;
     struct berval **ber_values;

{
    int i=0, j=0;
    krb5_error_code   st=0;

    if ((st=krb5_add_member(mods, &i)) != 0)
      return st;
    
    (*mods)[i]->mod_type = strdup(attribute);
    if ((*mods)[i]->mod_type == NULL)
      return ENOMEM;
    (*mods)[i]->mod_op = op;

    for (j=0; ber_values[j] != NULL; ++j)
      ;
    (*mods)[i]->mod_bvalues = malloc (sizeof(struct berval *) * (j+1));  
    if ((*mods)[i]->mod_bvalues == NULL)
	return ENOMEM;
    
    for (j=0; ber_values[j] != NULL; ++j) {
	(*mods)[i]->mod_bvalues[j] = calloc(1, sizeof(struct berval));
	if ((*mods)[i]->mod_bvalues[j] == NULL)
	    return ENOMEM;

	(*mods)[i]->mod_bvalues[j]->bv_len = ber_values[j]->bv_len;      
	(*mods)[i]->mod_bvalues[j]->bv_val = malloc((*mods)[i]->mod_bvalues[j]->bv_len);
	if ((*mods)[i]->mod_bvalues[j]->bv_val == NULL)
	    return ENOMEM;

	memcpy((*mods)[i]->mod_bvalues[j]->bv_val, ber_values[j]->bv_val, 
	       ber_values[j]->bv_len);
    }
    (*mods)[i]->mod_bvalues[j] = NULL;
    return 0;
}

static inline char *
format_d (int val)
{
    char tmpbuf[2+3*sizeof(val)];
    sprintf(tmpbuf, "%d", val);
    return strdup(tmpbuf);
}

krb5_error_code
krb5_add_int_arr_mem_ldap_mod(mods, attribute, op, value) 
     LDAPMod  ***mods;
     char     *attribute;
     int      op;
     int      *value;

{
    int i=0, j=0;
    krb5_error_code   st=0;

    if ((st=krb5_add_member(mods, &i)) != 0)
      return st;

    (*mods)[i]->mod_type = strdup(attribute);
    if ((*mods)[i]->mod_type == NULL)
      return ENOMEM;
    (*mods)[i]->mod_op = op;

    for (j=0; value[j] != -1; ++j)
      ;

    (*mods)[i]->mod_values = malloc(sizeof(char *) * (j+1));  
    
    for (j=0; value[j] != -1; ++j) {
	if (((*mods)[i]->mod_values[j] = format_d(value[j])) == NULL)
	    return ENOMEM;
    }
    (*mods)[i]->mod_values[j] = NULL;
    return 0;
}

krb5_error_code
krb5_add_int_mem_ldap_mod(mods, attribute, op, value) 
     LDAPMod  ***mods;
     char     *attribute;
     int      op;
     int      value;

{
    int i=0;
    krb5_error_code      st=0;

    if ((st=krb5_add_member(mods, &i)) != 0)
      return st;
    
    (*mods)[i]->mod_type = strdup(attribute);
    if ((*mods)[i]->mod_type == NULL)
      return ENOMEM;

    (*mods)[i]->mod_op = op;
    (*mods)[i]->mod_values = calloc (2, sizeof(char *));
    if (((*mods)[i]->mod_values[0] = format_d(value)) == NULL)
	return ENOMEM;
    return 0;
}
