/*
 * lib/kadm/adm_conn.c
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 */
/*
 * Routines to contact an administrative protocol server.
 */
#define	NEED_SOCKETS
#define	NEED_LOWLEVEL_IO
#include "k5-int.h"
#include "adm.h"
#include "adm_proto.h"

#if	HAVE_PWD_H
#include <pwd.h>
#endif	/* HAVE_PWD_H */

/* Default ticket life is 10 minutes */
#define	KADM_DEFAULT_LIFETIME	(10*60)

/*
 * Strings
 */
#define kadm_cache_name_fmt	"FILE:/tmp/tkt_kadm_%d"

/*
 * Prototypes for local functions
 */
static krb5_error_code kadm_get_ccache
	(krb5_context,
		   char *,
		   char *,
		   krb5_ccache *,
		   krb5_principal *);
static krb5_error_code kadm_get_creds
	(krb5_context,
		krb5_ccache ,
		krb5_principal,
		krb5_creds  *,
		const char *,
		char *,
		krb5_timestamp);
static krb5_error_code kadm_contact_server
	(krb5_context,
		krb5_data *,
		int *,
		krb5_address **,
		krb5_address **);
static krb5_error_code kadm_get_auth
	(krb5_context,
		krb5_auth_context *,
		krb5_address *,
		krb5_address *);

/*
 * kadm_get_ccache()	- Initialze a credentials cache.
 * 
 * Cleanup after success by calling krb5_cc_destroy() and krb5_free_principal()
 * Allocates new ccache and client.
 */
static krb5_error_code
kadm_get_ccache(kcontext, user, ccname, ccache, client)
    krb5_context	kcontext;
    char		*user;
    char		*ccname;
    krb5_ccache		*ccache;
    krb5_principal	*client;
{
    krb5_error_code	kret;
    char		*name;
    int 		did_malloc = 0;
    char		new_cache[MAXPATHLEN];
    krb5_principal	tprinc;

    /* Initialize. */
    *client = (krb5_principal) NULL;
    tprinc = (krb5_principal) NULL;

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
    kret = krb5_parse_name(kcontext, name, client);
    if (kret)
	goto cleanup;

    if (!ccname) {
#if defined(_WIN32)
	strcpy (new_cache, "FILE:");
	GetTempFileName (0, "tkt", 0, new_cache+5);
#else
#ifdef _MACINTOSH
	(void) sprintf(new_cache, "STDIO:admcc");
#else
	(void) sprintf(new_cache, kadm_cache_name_fmt, (int) getpid());
#endif /* _MACINTOSH */
#endif /* _WIN32 */
    }
    else
	sprintf(new_cache, "FILE:%s", ccname);

    /*
     * We only need to resolve the credentials cache if one hasn't
     * been supplied to us.
     */
    if (!(*ccache) && (kret = krb5_cc_resolve(kcontext, new_cache, ccache)))
	goto cleanup;

    /* XXX assumes a file ccache */
    if ((kret = krb5_cc_get_principal(kcontext, *ccache, &tprinc)) ==
	KRB5_FCC_NOFILE)
	kret = krb5_cc_initialize(kcontext, *ccache, *client);


 cleanup:
    if (did_malloc)
	free(name);

    if (tprinc)
	krb5_free_principal(kcontext, tprinc);

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
kadm_get_creds(kcontext, ccache, client, creds, prompt, oldpw, tlife)
    krb5_context	kcontext;
    krb5_ccache		ccache;
    krb5_principal	client;
    krb5_creds		*creds;
    const char		*prompt;
    char		*oldpw;
    krb5_timestamp	tlife;
{
    char		*client_name;
    krb5_error_code	kret;
    krb5_address	**my_addresses;
    unsigned int	old_pwsize;
    krb5_creds		tcreds;

    /* Initialize */
    my_addresses = (krb5_address **) NULL;
    client_name = (char *) NULL;

    /* Get the string form for our principal */
    kret = krb5_unparse_name(kcontext, client, &client_name);
    if (kret)
	return(kret);

    kret = krb5_os_localaddr(kcontext, &my_addresses);
    if (kret)
	goto cleanup;

    creds->client = client;
    /*
     * Build server principal name:
     *	"changepw" is service
     *	realm name is instance
     *	realm name is realm name
     */
    kret = krb5_build_principal_ext(kcontext,
				    &creds->server,
				    client->realm.length,
				    client->realm.data,
				    strlen(KRB5_ADM_SERVICE_INSTANCE),
				    KRB5_ADM_SERVICE_INSTANCE,
				    client->realm.length,
				    client->realm.data,
				    0);
    if (kret)
	goto cleanup;

    /* Attempt to retrieve an appropriate entry from the credentials cache. */
    if ((kret = krb5_cc_retrieve_cred(kcontext,
				      ccache,
				      KRB5_TC_MATCH_SRV_NAMEONLY,
				      creds,
				      &tcreds))
	== KRB5_CC_NOTFOUND) {
	krb5_timestamp	jetzt;

	if (prompt != (char *) NULL) {
	    /* Read the password */
	    old_pwsize = KRB5_ADM_MAX_PASSWORD_LEN;
	    kret = krb5_read_password(kcontext, prompt, (char *) NULL,
					  oldpw, &old_pwsize);
	    if (kret)
		goto cleanup;
	}

	kret = krb5_timeofday(kcontext, &jetzt);
	if (kret)
	    goto cleanup;

	if (tlife > 0)
	    creds->times.endtime = jetzt + tlife;
	else
	    creds->times.endtime = jetzt + KADM_DEFAULT_LIFETIME;

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
    }
    else {
	krb5_principal sclient, sserver;

	if (!kret) {
	    /*
	     * We found the credentials cache entry - copy it out.
	     *
	     * We'd like to just blast tcreds on top of creds, but we cannot.
	     * other logic uses the client data, and rather than going and
	     * chasing all that logic down, might as well pretend that we just
	     * filled in all the other muck.
	     */
	    sclient = creds->client;
	    sserver = creds->server;
	    memcpy((char *) creds, (char *) &tcreds, sizeof(tcreds));
	    if (creds->client)
		krb5_free_principal(kcontext, creds->client);
	    if (creds->server)
		krb5_free_principal(kcontext, creds->server);
	    creds->client = sclient;
	    creds->server = sserver;
	}
    }

 cleanup:
    if (kret) {
	if (creds->server) {
	    krb5_free_principal(kcontext, creds->server);
	    creds->server = 0;
	}
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
    int			i, count;

    krb5_error_code	kret;

    struct sockaddr_in	in_local;
    struct sockaddr_in	in_remote;
    socklen_t		addr_len;

    const char		*realm_admin_names[4];
    char		*realm_name;
    krb5_boolean	found;

    /* Initialize */
    hostlist = (char **) NULL;
    *sockp = -1;
    realm_name = (char *) NULL;

    /*
     * XXX - only know ADDRTYPE_INET.
     */
#ifdef	HAVE_NETINET_IN_H
    *local = (krb5_address *) malloc(sizeof(krb5_address));
    *remote = (krb5_address *) malloc(sizeof(krb5_address));
    realm_name = (char *) malloc((size_t) realmp->length + 1);
    if ((*local == (krb5_address *) NULL) ||
	(*remote == (krb5_address *) NULL) ||
	(realm_name == (char *) NULL)) {
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

    /*
     * First attempt to find addresses from our config file, if we cannot
     * find an entry, then try getservbyname().
     */
    found = 0;
#ifndef	OLD_CONFIG_FILES
    strncpy(realm_name, realmp->data, (size_t) realmp->length);
    realm_name[realmp->length] = '\0';
    realm_admin_names[0] = "realms";
    realm_admin_names[1] = realm_name;
    realm_admin_names[2] = "admin_server";
    realm_admin_names[3] = (char *) NULL;
    if (!(kret = profile_get_values(kcontext->profile,
				    realm_admin_names,
				    &hostlist))) {
	int		hi;
	char		*cport;
	char		*cp;
	krb5_int32	pport;

	for (hi = 0; hostlist[hi]; hi++) {
	    /*
	     * This knows a little too much about the format of profile
	     * entries.  Shouldn't it just be some sort of tuple?
	     *
	     * The form is assumed to be:
	     *	admin_server = <hostname>[:<portname>[<whitespace>]]
	     */
	    cport = (char *) NULL;
	    pport = (u_short) KRB5_ADM_DEFAULT_PORT;
	    cp = strchr(hostlist[hi], ' ');
	    if (cp)
		*cp = '\0';
	    cp = strchr(hostlist[hi], '\t');
	    if (cp)
		*cp = '\0';
	    cport = strchr(hostlist[hi], ':');
	    if (cport) {
		*cport = '\0';
		cport++;

		pport = atoi (cport);
		if (pport == 0) {
		    kret = KRB5_CONFIG_BADFORMAT;
		    goto cleanup;
		}
	    }

	    /*
	     * Now that we have a host name, get the host entry.
	     */
	    remote_host = gethostbyname(hostlist[hi]);
	    if (remote_host == (struct hostent *) NULL) {
		kret = KRB5_CONFIG_BADFORMAT;
		goto cleanup;
	    }

	    /*
	     * Fill in our address values.
	     */
	    in_remote.sin_family = remote_host->h_addrtype;
	    (void) memcpy((char *) &in_remote.sin_addr,
			  (char *) remote_host->h_addr,
			  sizeof(in_remote.sin_addr));
	    in_remote.sin_port = htons((u_short) pport);

	    /* Open a tcp socket */
	    *sockp = (int) socket(PF_INET, SOCK_STREAM, 0);
	    if (*sockp < 0) {
		kret = SOCKET_ERRNO;
		goto cleanup;
	    }
	    else kret = 0;

	    /* Attempt to connect to the remote address. */
	    if (connect(*sockp,
			(struct sockaddr *) &in_remote,
			sizeof(in_remote)) < 0) {
		/* Failed, go to next address */
		kret = SOCKET_ERRNO;
		closesocket((SOCKET)*sockp);
		*sockp = -1;
		continue;
	    }

	    /* Find out local address */
	    addr_len = sizeof(in_local);
	    if (getsockname((SOCKET) *sockp,
			    (struct sockaddr *) &in_local,
			    &addr_len) < 0) {
		/* Couldn't get our local address? */
		kret = SOCKET_ERRNO;
		goto cleanup;
	    }
	    else {
		/* Connection established. */
		memcpy((char *) (*remote)->contents,
		       (char *) &in_remote.sin_addr,
		       sizeof(struct in_addr));
		memcpy((char *) (*local)->contents,
		       (char *) &in_local.sin_addr,
		       sizeof(struct in_addr));
		found = 1;
		break;
	    }
	}
	if (!found) {
	    krb5_xfree(hostlist);
	    hostlist = (char **) NULL;
	}
    }
#endif	/* OLD_CONFIG_FILES */
    if (!found) {
	/*
	 * Use the old way of finding our administrative server.
	 *
	 * This consists of looking up an entry in /etc/services and if
	 * we don't find it, then we are just out of luck.  Then, we use
	 * that port number along with the address of the kdc.
	 */
	if ((service = getservbyname(KRB5_ADM_SERVICE_NAME, "tcp")) == NULL) {
	    kret = ENOENT;
	    goto cleanup;
	}
	in_remote.sin_port = service->s_port;
	
	kret = krb5_get_krbhst(kcontext, realmp, &hostlist);
	if (kret)
	    goto cleanup;
	
	/* Now count the number of hosts in the realm */
	count = 0;
	for (i=0; hostlist[i]; i++)
	    count++;
	if (count == 0) {
	    kret = ENOENT;	/* something better? */
	    goto cleanup;
	}
	
	/* Now find an available host */
	for (i=0; hostlist[i]; i++) {
	    remote_host = gethostbyname(hostlist[i]);
	    if (remote_host != (struct hostent *) NULL) {
		in_remote.sin_family = remote_host->h_addrtype;
		(void) memcpy((char *) &in_remote.sin_addr,
			      (char *) remote_host->h_addr,
			      sizeof(in_remote.sin_addr));
	
		/* Open a tcp socket */
		*sockp = (int) socket(PF_INET, SOCK_STREAM, 0);
		if (*sockp < 0) {
		    kret = SOCKET_ERRNO;
		    goto cleanup;
		}
		else kret = 0;
	
		if (connect(*sockp,
			    (struct sockaddr *) &in_remote,
			    sizeof(in_remote)) < 0) {
		    kret = SOCKET_ERRNO;
		    closesocket((SOCKET)*sockp);
		    *sockp = -1;
		    continue;
		}

		/* Find out local address */
		addr_len = sizeof(in_local);
		if (getsockname((SOCKET)*sockp,
				(struct sockaddr *) &in_local,
				&addr_len) < 0) {
		    kret = SOCKET_ERRNO;
		    goto cleanup;
		}
		else {
		    memcpy((char *) (*remote)->contents,
			   (char *) &in_remote.sin_addr,
			   sizeof(struct in_addr));
	
		    memcpy((char *) (*local)->contents,
			   (char *) &in_local.sin_addr,
			   sizeof(struct in_addr));
		    found = 1;
		    break;
		}
	    }
	}
	if (!found)
	    kret = KRB5_SERVICE_UNKNOWN;
    }
#else	/* HAVE_NETINET_IN_H */
    kret = ENOENT;
#endif	/* HAVE_NETINET_IN_H */

 cleanup:
    if (kret) {
	if (*sockp >= 0)
	    closesocket((SOCKET)*sockp);
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
    if (realm_name)
	free(realm_name);
    if (hostlist)
	krb5_xfree(hostlist);
    return(kret);
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
    krb5_auth_context	*ctxp;
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
 * If *ccachep is not null, then that ccache is used to establish the identity
 * of the caller.  (Argument list is ugly, I know)
 *
 * Errors are not reported by this routine.
 * Cleanup after successful invocation must:
 *	destroy/close ccache.
 *	free auth_context
 *	close socket.
 */
krb5_error_code KRB5_CALLCONV
krb5_adm_connect(kcontext, user, prompt, opassword, sockp, ctxp,
		 ccachep, ccname, tlife)
    krb5_context	kcontext;	/* Context handle	(In ) */
    char		*user;		/* User specified	(In ) */
    const char		*prompt;	/* Old password prompt	(In ) */
    char		*opassword;	/* Old Password		(I/O) */
    int			*sockp;		/* Socket for conn.	(Out) */
    krb5_auth_context	*ctxp;		/* Auth context		(Out) */
    krb5_ccache		*ccachep;	/* Credentials cache	(I/O) */
    char		*ccname;	/* Cred cache name	(In ) */
    krb5_timestamp	tlife;		/* Ticket lifetime	(In ) */
{
    krb5_error_code	kret;
    krb5_principal	client;
    krb5_creds		creds;
    krb5_data		server_realm;
    krb5_data		request_data, suppl_data;
    krb5_data		response_data;
    krb5_address	*local_addr;
    krb5_address	*remote_addr;
    krb5_boolean	ccache_supplied;

    char		*server;

    /* Initialize */
    memset((char *) &creds, 0, sizeof(krb5_creds));
    server = (char *) NULL;
    *sockp = -1;
    local_addr = remote_addr = (krb5_address *) NULL;
    client = (krb5_principal) NULL;
    *ctxp = (krb5_auth_context) NULL;
    ccache_supplied = (*ccachep != (krb5_ccache) NULL);

    /*
     * Find the appropriate credentials cache and set up our identity.
     */
    kret = kadm_get_ccache(kcontext, user, ccname, ccachep, &client);
    if (kret)
	goto cleanup;

    /*
     * Get initial credentials.
     */
    kret = kadm_get_creds(kcontext, *ccachep, client, &creds,
			      prompt, opassword, tlife);
    if (kret)
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

    kret = kadm_contact_server(kcontext, &server_realm, sockp,
			       &local_addr, &remote_addr);
    if (kret)
	goto cleanup;

    /*
     * Obtain our authorization context
     */
    kret = kadm_get_auth(kcontext, ctxp, local_addr, remote_addr);
    if (kret)
	goto cleanup;

    /*
     * Format, then send the KRB_AP_REQ
     */
    suppl_data.data = NULL;
    suppl_data.length = 0;

    kret = krb5_mk_req_extended(kcontext, ctxp, AP_OPTS_MUTUAL_REQUIRED,
				&suppl_data, &creds, &request_data);
    if (kret)
	goto cleanup;

    kret = krb5_write_message(kcontext, sockp, &request_data);
    if (kret)
	goto cleanup;

    /*
     * Now read back the response.
     */
    kret = krb5_read_message(kcontext, sockp, &response_data);
    if (kret) {
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
	    *ctxp = (krb5_auth_context) NULL;
	}
	if (*sockp >= 0) {
	    closesocket((SOCKET)*sockp);
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
	if (*ccachep && !ccache_supplied) {
	    krb5_cc_destroy(kcontext, *ccachep);
	    *ccachep = (krb5_ccache) NULL;
	}
    }
    return(kret);

}

/*
 * krb5_adm_disconnect()	- Disconnect from the administrative service.
 *
 * If ccache is supplied, then it is destroyed.  Otherwise, the ccache is
 * the caller's responsibility to close.
 */
void KRB5_CALLCONV
krb5_adm_disconnect(kcontext, socketp, auth_context, ccache)
    krb5_context	kcontext;
    int			*socketp;
    krb5_auth_context	auth_context;
    krb5_ccache		ccache;
{
    if (ccache)
	krb5_cc_destroy(kcontext, ccache);
    if (auth_context)
	krb5_xfree(auth_context);
    if (*socketp >= 0)
	closesocket((SOCKET)*socketp);
}

