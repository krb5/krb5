/*
 * lib/krb5/os/changepw.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
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

#define NEED_SOCKETS
#include "k5-int.h"
#include "adm_err.h"

#include <stdio.h>
#include <errno.h>

/* Win32 defines. */
#if defined(_WIN16) || (defined(_WIN32) && !defined(__CYGWIN32__))
#ifndef ECONNABORTED
#define ECONNABORTED WSAECONNABORTED
#endif
#ifndef ECONNREFUSED
#define ECONNREFUSED WSAECONNREFUSED
#endif
#ifndef EHOSTUNREACH
#define EHOSTUNREACH WSAEHOSTUNREACH
#endif
#endif /* _WIN32 && !__CYGWIN32__ */

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_change_password(context, creds, newpw, result_code,
		     result_code_string, result_string)
    krb5_context context;
    krb5_creds *creds;
    char *newpw;
    int *result_code;
    krb5_data *result_code_string;
    krb5_data *result_string;
{
    krb5_auth_context auth_context;
    krb5_data ap_req, chpw_req, chpw_rep;
    krb5_address local_kaddr, remote_kaddr;
    const char *realm_kdc_names[4];
    int default_port;
    char **hostlist, *host, *port, *cp, *code_string;
    krb5_error_code code;
    int i, j, out, count, addrlen;
    struct sockaddr *addr_p, local_addr, remote_addr, tmp_addr;
    struct sockaddr_in *sin_p;
    struct hostent *hp;
    struct servent *sp;
#ifdef HAVE_NETINET_IN_H
    u_short udpport = htons(KRB5_DEFAULT_PORT);
#endif
    int cc, local_result_code, tmp_len;
    SOCKET s1, s2;

    auth_context = NULL;

    if (code = krb5_mk_req_extended(context, &auth_context, AP_OPTS_USE_SUBKEY,
				    NULL, creds, &ap_req))
	return(code);

    if ((host = malloc(krb5_princ_realm(context, creds->client)->length + 1))
	== NULL) 
	return ENOMEM;

    strncpy(host, krb5_princ_realm(context, creds->client)->data,
	    krb5_princ_realm(context, creds->client)->length);
    host[krb5_princ_realm(context, creds->client)->length] = '\0';
    hostlist = 0;
    
    realm_kdc_names[0] = "realms";
    realm_kdc_names[1] = host;
    realm_kdc_names[2] = "kpasswd_server";
    realm_kdc_names[3] = 0;

    default_port = 0;

    code = profile_get_values(context->profile, realm_kdc_names, &hostlist);

    if (code == PROF_NO_RELATION) {
	realm_kdc_names[2] = "admin_server";

	default_port = 1;

	code = profile_get_values(context->profile, realm_kdc_names,
				  &hostlist);
    }

    krb5_xfree(host);

    if (code == PROF_NO_SECTION)
	return KRB5_REALM_UNKNOWN;
    else if (code == PROF_NO_RELATION)
	return KRB5_CONFIG_BADFORMAT;
    else if (code)
	return code;

#ifdef HAVE_NETINET_IN_H
    /* XXX should look for "kpasswd" in /etc/services */
    udpport = htons(DEFAULT_KPASSWD_PORT);
#endif

    count = 0;
    while (hostlist && hostlist[count])
	    count++;
    
    if (count == 0)
	/* XXX */
	return(KADM_NO_HOST);
    
    addr_p = (struct sockaddr *) malloc(sizeof(struct sockaddr) * count);
    if (addr_p == NULL)
        return ENOMEM;

    host = hostlist[0];
    out = 0;

    /*
     * Strip off excess whitespace
     */
    cp = strchr(host, ' ');
    if (cp)
	*cp = 0;
    cp = strchr(host, '\t');
    if (cp)
	*cp = 0;
    port = strchr(host, ':');
    if (port) {
	*port = 0;
	port++;
	/* if the admin_server line was used, ignore the specified
           port */
	if (default_port)
	    port = NULL;
    }
    hp = gethostbyname(hostlist[0]);

    if (hp != 0) {
	switch (hp->h_addrtype) {
#ifdef HAVE_NETINET_IN_H
	case AF_INET:
	    for (j=0; hp->h_addr_list[j]; j++) {
		sin_p = (struct sockaddr_in *) &addr_p[out++];
		memset ((char *)sin_p, 0, sizeof(struct sockaddr));
		sin_p->sin_family = hp->h_addrtype;
		sin_p->sin_port = port ? htons(atoi(port)) : udpport;
		memcpy((char *)&sin_p->sin_addr,
		       (char *)hp->h_addr_list[j],
		       sizeof(struct in_addr));
		if (out+1 >= count) {
		    count += 5;
		    addr_p = (struct sockaddr *)
			realloc ((char *)addr_p,
				 sizeof(struct sockaddr) * count);
		    if (addr_p == NULL)
			return ENOMEM;
		}
	    }
	    break;
#endif
	default:
	    break;
	}
    }

    for (i=0; hostlist[i]; i++)
	free(hostlist[i]);
    free ((char *)hostlist);

    if (out == 0) {     /* Couldn't resolve any KDC names */
        free (addr_p);
        return(KADM_NO_HOST);
    }

    /* this is really obscure.  s1 is used for all communications.  it
       is left unconnected in case the server is multihomed and routes
       are asymmetric.  s2 is connected to resolve routes and get
       addresses.  this is the *only* way to get proper addresses for
       multihomed hosts if routing is asymmetric.  

       A related problem in the server, but not the client, is that
       many os's have no way to disconnect a connected udp socket, so
       the s2 socket needs to be closed and recreated for each
       request.  The s1 socket must not be closed, or else queued
       requests will be lost.

       A "naive" client implementation (one socket, no connect,
       hostname resolution to get the local ip addr) will work and
       interoperate if the client is single-homed. */

    if ((s1 = socket(AF_INET, SOCK_DGRAM, 0)) == INVALID_SOCKET) {
	free(addr_p);
	return(SOCKET_ERRNO);
    }

    if ((s2 = socket(AF_INET, SOCK_DGRAM, 0)) == INVALID_SOCKET) {
	free(addr_p);
	return(SOCKET_ERRNO);
    }

    for (i=0; i<out; i++) {
	if (connect(s2, &addr_p[i], sizeof(addr_p[i])) == SOCKET_ERROR) {
	    if ((cc < 0) && ((SOCKET_ERRNO == ECONNREFUSED) ||
			     (SOCKET_ERRNO == EHOSTUNREACH)))
		continue; /* try the next addr */
	    free(addr_p);
	    closesocket(s1);
	    closesocket(s2);
	    return(SOCKET_ERRNO);
	}

	addrlen = sizeof(local_addr);

	if (getsockname(s2, &local_addr, &addrlen) < 0) {
	    if ((SOCKET_ERRNO == ECONNREFUSED) ||
		(SOCKET_ERRNO == EHOSTUNREACH))
		continue; /* try the next addr */
	    free(addr_p);
	    closesocket(s1);
	    closesocket(s2);
	    return(SOCKET_ERRNO);
	}

	/* some brain-dead OS's don't return useful information from
	 * the getsockname call.  Namely, windows and solaris.  */

	if (((struct sockaddr_in *)&local_addr)->sin_addr.s_addr != 0) {
	    local_kaddr.addrtype = ADDRTYPE_INET;
	    local_kaddr.length =
	      sizeof(((struct sockaddr_in *) &local_addr)->sin_addr);
	    local_kaddr.contents = 
	      (krb5_octet *) &(((struct sockaddr_in *) &local_addr)->sin_addr);
	} else {
	    krb5_address **addrs;

	    krb5_os_localaddr(context, &addrs);
	    local_kaddr.magic = addrs[0]->magic;
	    local_kaddr.addrtype = addrs[0]->addrtype;
	    local_kaddr.length = addrs[0]->length;
	    local_kaddr.contents = malloc(addrs[0]->length);
	    memcpy(local_kaddr.contents, addrs[0]->contents, addrs[0]->length);

	    krb5_free_addresses(context, addrs);
	}

	addrlen = sizeof(remote_addr);
	if (getpeername(s2, &remote_addr, &addrlen) < 0) {
	    if ((SOCKET_ERRNO == ECONNREFUSED) ||
		(SOCKET_ERRNO == EHOSTUNREACH))
		continue; /* try the next addr */
	    free(addr_p);
	    closesocket(s1);
	    closesocket(s2);
	    return(SOCKET_ERRNO);
	}

	remote_kaddr.addrtype = ADDRTYPE_INET;
	remote_kaddr.length =
	    sizeof(((struct sockaddr_in *) &remote_addr)->sin_addr);
	remote_kaddr.contents = 
	    (krb5_octet *) &(((struct sockaddr_in *) &remote_addr)->sin_addr);

	/* mk_priv requires that the local address be set.
	  getsockname is used for this.  rd_priv requires that the
	  remote address be set.  recvfrom is used for this.  If
	  rd_priv is given a local address, and the message has the
	  recipient addr in it, this will be checked.  However, there
	  is simply no way to know ahead of time what address the
	  message will be delivered *to*.  Therefore, it is important
	  that either no recipient address is in the messages when
	  mk_priv is called, or that no local address is passed to
	  rd_priv.  Both is a better idea, and I have done that.  In
	  summary, when mk_priv is called, *only* a local address is
	  specified.  when rd_priv is called, *only* a remote address
	  is specified.  Are we having fun yet?  */

	if (code = krb5_auth_con_setaddrs(context, auth_context, &local_kaddr,
					  NULL)) {
	    free(addr_p);
	    closesocket(s1);
	    closesocket(s2);
	    return(code);
	}

	if (code = krb5_mk_chpw_req(context, auth_context, &ap_req,
				    newpw, &chpw_req)) {
	    free(addr_p);
	    closesocket(s1);
	    closesocket(s2);
	    return(code);
	}

	if ((cc = sendto(s1, chpw_req.data, chpw_req.length, 0,
			 (struct sockaddr *) &addr_p[i],
			 sizeof(addr_p[i]))) !=
	    chpw_req.length) {
	    if ((cc < 0) && ((SOCKET_ERRNO == ECONNREFUSED) ||
			     (SOCKET_ERRNO == EHOSTUNREACH)))
		continue; /* try the next addr */
	    free(addr_p);
	    closesocket(s1);
	    closesocket(s2);
	    return((cc < 0)?SOCKET_ERRNO:ECONNABORTED);
	}

	krb5_xfree(chpw_req.data);

	chpw_rep.length = 1500;
	chpw_rep.data = (char *) malloc(chpw_rep.length);

	/* XXX need a timeout/retry loop here */

	/* "recv" would be good enough here... except that Windows/NT
	   commits the atrocity of returning -1 to indicate failure,
	   but leaving errno set to 0.
	   
	   "recvfrom(...,NULL,NULL)" would seem to be a good enough
	   alternative, and it works on NT, but it doesn't work on
	   SunOS 4.1.4 or Irix 5.3.  Thus we must actually accept the
	   value and discard it. */
	tmp_len = sizeof(tmp_addr);
	if ((cc = recvfrom(s1, chpw_rep.data, chpw_rep.length, 0, &tmp_addr, &tmp_len)) < 0) {
	    free(addr_p);
	    closesocket(s1);
	    closesocket(s2);
	    return(SOCKET_ERRNO);
	}

	closesocket(s1);
	closesocket(s2);

	chpw_rep.length = cc;

	if (code = krb5_auth_con_setaddrs(context, auth_context, NULL,
					  &remote_kaddr)) {
	    free(addr_p);
	    closesocket(s1);
	    closesocket(s2);
	    return(code);
	}

	code = krb5_rd_chpw_rep(context, auth_context, &chpw_rep,
				&local_result_code, result_string);

	free(chpw_rep.data);
	free(addr_p);

	if (code)
	    return(code);

	if (result_code)
	    *result_code = local_result_code;

	if (result_code_string) {
	    if (code = krb5_chpw_result_code_string(context, local_result_code,
						    &code_string))
		return(code);

	    result_code_string->length = strlen(code_string);
	    if ((result_code_string->data =
		 (char *) malloc(result_code_string->length)) == NULL)
		return(ENOMEM);
	    strncpy(result_code_string->data, code_string,
		    result_code_string->length);
	}

	return(0);
    }

    free(addr_p);
    closesocket(s1);
    closesocket(s2);
    return(SOCKET_ERRNO);
}
