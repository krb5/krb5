/*
 * lib/krb5/os/adm_conn.c
 *
 * Copyright 1995 by the Massachusetts Institute of Technology.
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
/*
 * Routines to contact an administrative protocol server.
 */
#define	NEED_SOCKETS
#include "k5-int.h"
#include "adm.h"
#include "adm_proto.h"

#if	HAVE_PWD_H
#include <pwd.h>
#endif	/* HAVE_PWD_H */

/*
 * Strings
 */
static char *kadm_cache_name_fmt =	"FILE:/tmp/tkt_kpw_%d";

/*
 * kadm_get_ccache()	- Initialze a credentials cache.
 * 
 * Cleanup after success by calling krb5_cc_destroy() and krb5_free_principal()
 * Allocates new ccache and client.
 */
static krb5_error_code
kadm_get_ccache(kcontext, user, ccache, client)
    krb5_context	kcontext;
    char		*user;
    krb5_ccache		*ccache;
    krb5_principal	*client;
{
    krb5_error_code	kret;
    char		*name;
    int 		did_malloc = 0;
    char		new_cache[MAXPATHLEN];

    /* Initialize. */
    *client = (krb5_principal) NULL;

    /*
     * If a name specified, then use that one, else get it from our
     * current uid.
     */
    if (user) {
	name = user;
    }
    else {
#if	HAVE_PWD_H
	struct passwd *pw;

	pw = getpwuid(getuid());
	if (pw) {
	    name = (char *) malloc(strlen(pw->pw_name)+1);
	    did_malloc = 1;
	    strcpy(name, pw->pw_name);
	}
	else {
	    kret = errno;
	    goto cleanup;
	}
#else	/* HAVE_PWD_H */
	kret = ENOENT;
	goto cleanup;
#endif	/* HAVE_PWD_H */
    }

    /* Parse the name and form our principal */
    if (kret = krb5_parse_name(kcontext, name, client))
	goto cleanup;

    (void) sprintf(new_cache, kadm_cache_name_fmt, getpid());
    if (kret = krb5_cc_resolve(kcontext, new_cache, ccache))
	goto cleanup;

    kret = krb5_cc_initialize(kcontext, *ccache, *client);

 cleanup:
    if (did_malloc)
	free(name);

    if (kret) {
	if (*client)
	    krb5_free_principal(kcontext, *client);
    }

    return(kret);
}

/*
 * kadm_get_creds()	- Get initial credentials.
 *
 * Cleanup after success by calling krb5_free_principal().
 * Allocates new principal for creds->server.
 */
static krb5_error_code
kadm_get_creds(kcontext, ccache, client, creds, prompt, oldpw)
    krb5_context	kcontext;
    krb5_ccache		ccache;
    krb5_principal	client;
    krb5_creds		*creds;
    char		*prompt;
    char		*oldpw;
{
    char		*client_name;
    krb5_error_code	kret;
    krb5_address	**my_addresses;
    int			old_pwsize;

    /* Initialize */
    my_addresses = (krb5_address **) NULL;
    client_name = (char *) NULL;

    /* Get the string form for our principal */
    if (kret = krb5_unparse_name(kcontext, client, &client_name))
	return(kret);

    if (kret = krb5_os_localaddr(&my_addresses))
	goto cleanup;

    creds->client = client;
    /*
     * Build server principal name:
     *	"changepw" is service
     *	realm name is instance
     *	realm name is realm name
     */
    if (kret = krb5_build_principal_ext(kcontext,
					&creds->server,
					client->realm.length,
					client->realm.data,
					strlen(KRB5_ADM_SERVICE_NAME),
					KRB5_ADM_SERVICE_NAME,
					client->realm.length,
					client->realm.data,
					0))
	goto cleanup;

    if (prompt != (char *) NULL) {
	/* Read the password */
	old_pwsize = KRB5_ADM_MAX_PASSWORD_LEN;
	if (kret = krb5_read_password(kcontext,
				      prompt,
				      (char *) NULL,
				      oldpw,
				      &old_pwsize))
	    goto cleanup;
    }

    /* Get our initial ticket */
    kret = krb5_get_in_tkt_with_password(kcontext,
					 0,
					 my_addresses,
					 NULL,
					 NULL,
					 oldpw,
					 ccache,
					 creds,
					 0);

 cleanup:
    if (kret) {
	if (creds->server)
	    krb5_free_principal(kcontext, creds->server);
    }
    if (my_addresses)
	krb5_free_addresses(kcontext, my_addresses);
    if (client_name)
	krb5_xfree(client_name);
    return(kret);
}

/*
 * kadm_contact_server()	- Establish a connection to the server.
 *
 * Cleanup after success by calling close() and free().
 * Opens/connects socket *sockp.  Allocates address storage for local/remote.
 */
static krb5_error_code
kadm_contact_server(kcontext, realmp, sockp, local, remote)
    krb5_context	kcontext;
    krb5_data		*realmp;
    int			*sockp;
    krb5_address	**local;
    krb5_address	**remote;
{
    struct hostent	*remote_host;
    struct servent	*service;
    char 		**hostlist;
    int			host_count;
    int			namelen;
    int			i, count;

    krb5_error_code	kret;

    struct sockaddr_in	in_local;
    struct sockaddr_in	in_remote;
    int			addr_len;

    /* Initialize */
    hostlist = (char **) NULL;
    *sockp = -1;

    /*
     * XXX - only know ADDRTYPE_INET.
     */
#ifdef	KRB5_USE_INET
    *local = (krb5_address *) malloc(sizeof(krb5_address));
    *remote = (krb5_address *) malloc(sizeof(krb5_address));
    if ((*local == NULL) || (*remote == NULL)) {
	kret = ENOMEM;
	goto cleanup;
    }
    (*local)->addrtype = (*remote)->addrtype = ADDRTYPE_INET;
    (*local)->length = (*remote)->length = sizeof(struct in_addr);
    (*local)->contents = (krb5_octet *) malloc(sizeof(struct in_addr));
    (*remote)->contents = (krb5_octet *) malloc(sizeof(struct in_addr));
    if (((*local)->contents == NULL) || ((*remote)->contents == NULL)) {
	kret = ENOMEM;
	goto cleanup;
    }

    if ((service = getservbyname(KRB5_ADM_SERVICE_NAME, "tcp")) == NULL) {
	kret = ENOENT;
	goto cleanup;
    }
    in_remote.sin_port = service->s_port;
#endif	/* KRB5_USE_INET */

    if (kret = krb5_get_krbhst(kcontext, realmp, &hostlist))
	goto cleanup;

    /* Now count the number of hosts in the realm */
    count = 0;
    for (i=0; hostlist[i]; i++)
      count++;
    if (count == 0) {
	kret = ENOENT;	/* something better? */
	goto cleanup;
    }

#ifdef	KRB5_USE_INET
    /* Now find a suitable host */
    for (i=0; hostlist[i]; i++) {
	remote_host = gethostbyname(hostlist[i]);
	if (remote_host != (struct hostent *) NULL) {
	    in_remote.sin_family = remote_host->h_addrtype;
	    (void) memcpy((char *) &in_remote.sin_addr,
			  (char *) remote_host->h_addr,
			  sizeof(in_remote.sin_addr));
	    break;
	}
    }

    /* Open a tcp socket */
    *sockp = socket(PF_INET, SOCK_STREAM, 0);
    if (*sockp < 0) {
	kret = errno;
	goto cleanup;
    }
    else kret = 0;

    if (connect(*sockp,
		(struct sockaddr *) &in_remote,
		sizeof(in_remote)) < 0) {
	kret = errno;
	goto cleanup;
    }
    memcpy((char *) (*remote)->contents,
	   (char *) &in_remote.sin_addr,
	   sizeof(struct in_addr));

    /* Find out local address */
    addr_len = sizeof(in_local);
    if (getsockname(*sockp, (struct sockaddr *) &in_local, &addr_len) < 0)
	kret = errno;
    else
	memcpy((char *) (*local)->contents,
	       (char *) &in_local.sin_addr,
	       sizeof(struct in_addr));
#else	/* KRB5_USE_INET */
    kret = ENOENT;
#endif	/* KRB5_USE_INET */

 cleanup:
    if (kret) {
	if (*sockp >= 0)
	    close(*sockp);
	if (*local && (*local)->contents)
	    free((*local)->contents);
	if (*remote && (*remote)->contents)
	    free((*remote)->contents);
	if (*local) {
	    memset((char *) (*local), 0, sizeof(krb5_address));
	    free(*local);
	    *local = (krb5_address *) NULL;
	}
	if (*remote) {
	    memset((char *) (*remote), 0, sizeof(krb5_address));
	    free(*remote);
	    *remote = (krb5_address *) NULL;
	}
    }
    if (hostlist)
	krb5_xfree(hostlist);
    return(0);
}

/*
 * kadm_get_auth()	- Get authorization context.
 *
 * Cleanup after success by calling krb5_xfree().
 * New krb5_auth_context allocated in *ctxp
 */
static krb5_error_code
kadm_get_auth(kcontext, ctxp, local, remote)
    krb5_context	kcontext;
    krb5_auth_context	**ctxp;
    krb5_address	*local;
    krb5_address	*remote;
{
    krb5_auth_con_init(kcontext, ctxp);
    krb5_auth_con_setflags(kcontext, *ctxp, 
			   KRB5_AUTH_CONTEXT_RET_SEQUENCE|
			   KRB5_AUTH_CONTEXT_DO_SEQUENCE);
    krb5_auth_con_setaddrs(kcontext, *ctxp, local, remote);
    return(0);
}

/*
 * krb5_adm_connect()	- Establish the connection to the service.
 *
 * Errors are not reported by this routine.
 * Cleanup after successful invocation must:
 *	destroy ccache.
 *	free auth_context
 *	close socket.
 */
krb5_error_code INTERFACE
krb5_adm_connect(kcontext, user, prompt, opassword, sockp, ctxp, ccachep)
    krb5_context	kcontext;	/* Context handle	(In ) */
    char		*user;		/* User specified	(In ) */
    char		*prompt;	/* Old password prompt	(In ) */
    char		*opassword;	/* Old Password		(I/O) */
    int			*sockp;		/* Socket for conn.	(Out) */
    krb5_auth_context	**ctxp;		/* Auth context		(Out) */
    krb5_ccache		*ccachep;	/* Credentials cache	(Out) */
{
    krb5_error_code	kret;
    krb5_principal	client;
    krb5_creds		creds;
    krb5_data		server_realm;
    krb5_data		request_data, suppl_data;
    krb5_data		response_data;
    krb5_address	*local_addr;
    krb5_address	*remote_addr;

    char		*server;

    /* Initialize */
    memset((char *) &creds, 0, sizeof(krb5_creds));
    server = (char *) NULL;
    *sockp = -1;
    local_addr = remote_addr = (krb5_address *) NULL;
    client = (krb5_principal) NULL;
    *ctxp = (krb5_auth_context *) NULL;
    *ccachep = (krb5_ccache) NULL;

    /*
     * Find the appropriate credentials cache and set up our identity.
     */
    if (kret = kadm_get_ccache(kcontext, user, ccachep, &client))
	goto cleanup;

    /*
     * Get initial credentials.
     */
    if (kret = kadm_get_creds(kcontext,
			      *ccachep,
			      client,
			      &creds,
			      prompt,
			      opassword))
	goto cleanup;

    /*
     * Establish connection to server.
     */
    if ((server_realm.data = (char *) malloc(client->realm.length+1)) ==
	(char *) NULL)
	goto cleanup;

    server_realm.length = client->realm.length;
    memcpy(server_realm.data, client->realm.data, server_realm.length);
    server_realm.data[server_realm.length] = '\0';
    if (kret = kadm_contact_server(kcontext,
				   &server_realm,
				   sockp,
				   &local_addr,
				   &remote_addr))
	goto cleanup;

    /*
     * Obtain our authorization context
     */
    if (kret = kadm_get_auth(kcontext, ctxp, local_addr, remote_addr))
	goto cleanup;

    /*
     * Format, then send the KRB_AP_REQ
     */
    suppl_data.data = NULL;
    suppl_data.length = 0;
    if (kret = krb5_mk_req_extended(kcontext,
				    ctxp,
				    AP_OPTS_MUTUAL_REQUIRED,
				    &suppl_data,
				    &creds,
				    &request_data))
	goto cleanup;

    if (kret = krb5_write_message(kcontext, sockp, &request_data))
	goto cleanup;

    /*
     * Now read back the response.
     */
    if (kret = krb5_read_message(kcontext, sockp, &response_data)) {
	goto cleanup;
    }
    else {
	krb5_ap_rep_enc_part	*reply = NULL;

	kret = krb5_rd_rep(kcontext, *ctxp, &response_data, &reply);
	if (reply)
	    krb5_free_ap_rep_enc_part(kcontext, reply);
    }
 cleanup:
    if (server)
	free(server);
    if (kret) {
	if (*ctxp) {
	    krb5_xfree(*ctxp);
	    *ctxp = (krb5_auth_context *) NULL;
	}
	if (*sockp >= 0) {
	    close(*sockp);
	    *sockp = -1;
	}
	if (local_addr && local_addr->contents)
	    free(local_addr->contents);
	if (remote_addr && remote_addr->contents)
	    free(remote_addr->contents);
	if (local_addr)
	    free(local_addr);
	if (remote_addr)
	    free(remote_addr);
	if (creds.server)
	    krb5_free_principal(kcontext, creds.server);
	if (client)
	    krb5_free_principal(kcontext, client);
	if (*ccachep) {
	    krb5_cc_destroy(kcontext, *ccachep);
	    *ccachep = (krb5_ccache) NULL;
	}
    }
    return(kret);

}

/*
 * krb5_adm_disconnect()	- Disconnect from the administrative service.
 */
void INTERFACE
krb5_adm_disconnect(kcontext, socketp, auth_context, ccache)
    krb5_context	kcontext;
    int			*socketp;
    krb5_auth_context	*auth_context;
    krb5_ccache		ccache;
{
    if (ccache)
	krb5_cc_destroy(kcontext, ccache);
    if (auth_context)
	krb5_xfree(auth_context);
    if (*socketp >= 0)
	close(*socketp);
}

