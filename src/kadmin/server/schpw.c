#define NEED_SOCKETS
#include "k5-int.h"
#include <kadm5/admin.h>
#include <syslog.h>
#include <krb5/adm_proto.h>	/* krb5_klog_syslog */
#include <stdio.h>
#include <errno.h>

#include "misc.h"

#ifndef GETSOCKNAME_ARG3_TYPE
#define GETSOCKNAME_ARG3_TYPE int
#endif

krb5_error_code
process_chpw_request(context, server_handle, realm, s, keytab, sockin, 
		     req, rep)
     krb5_context context;
     void *server_handle;
     char *realm;
     int s;
     krb5_keytab keytab;
     struct sockaddr_in *sockin;
     krb5_data *req;
     krb5_data *rep;
{
    krb5_error_code ret;
    char *ptr;
    int plen, vno;
    krb5_address local_kaddr, remote_kaddr;
    int allocated_mem = 0;  
    krb5_data ap_req, ap_rep;
    krb5_auth_context auth_context;
    krb5_principal changepw;
    krb5_ticket *ticket;
    krb5_data cipher, clear;
    struct sockaddr local_addr, remote_addr;
    GETSOCKNAME_ARG3_TYPE addrlen;
    krb5_replay_data replay;
    krb5_error krberror;
    int numresult;
    char strresult[1024];
    char *clientstr;

    ret = 0;
    rep->length = 0;

    auth_context = NULL;
    changepw = NULL;
    ap_rep.length = 0;
    ticket = NULL;
    clear.length = 0;
    cipher.length = 0;

    if (req->length < 4) {
	/* either this, or the server is printing bad messages,
	   or the caller passed in garbage */
	ret = KRB5KRB_AP_ERR_MODIFIED;
	numresult = KRB5_KPASSWD_MALFORMED;
	strcpy(strresult, "Request was truncated");
	goto chpwfail;
    }

    ptr = req->data;

    /* verify length */

    plen = (*ptr++ & 0xff);
    plen = (plen<<8) | (*ptr++ & 0xff);

    if (plen != req->length)
	return(KRB5KRB_AP_ERR_MODIFIED);

    /* verify version number */

    vno = (*ptr++ & 0xff) ;
    vno = (vno<<8) | (*ptr++ & 0xff);

    if (vno != 1) {
	ret = KRB5KDC_ERR_BAD_PVNO;
	numresult = KRB5_KPASSWD_BAD_VERSION;
	sprintf(strresult,
		"Request contained unknown protocol version number %d", vno);
	goto chpwfail;
    }

    /* read, check ap-req length */

    ap_req.length = (*ptr++ & 0xff);
    ap_req.length = (ap_req.length<<8) | (*ptr++ & 0xff);

    if (ptr + ap_req.length >= req->data + req->length) {
	ret = KRB5KRB_AP_ERR_MODIFIED;
	numresult = KRB5_KPASSWD_MALFORMED;
	strcpy(strresult, "Request was truncated in AP-REQ");
	goto chpwfail;
    }

    /* verify ap_req */

    ap_req.data = ptr;
    ptr += ap_req.length;

    ret = krb5_auth_con_init(context, &auth_context);
    if (ret) {
	numresult = KRB5_KPASSWD_HARDERROR;
	strcpy(strresult, "Failed initializing auth context");
	goto chpwfail;
    }

    ret = krb5_auth_con_setflags(context, auth_context,
				 KRB5_AUTH_CONTEXT_DO_SEQUENCE);
    if (ret) {
	numresult = KRB5_KPASSWD_HARDERROR;
	strcpy(strresult, "Failed initializing auth context");
	goto chpwfail;
    }
	
    ret = krb5_build_principal(context, &changepw, strlen(realm), realm,
			       "kadmin", "changepw", NULL);
    if (ret) {
	numresult = KRB5_KPASSWD_HARDERROR;
	strcpy(strresult, "Failed building kadmin/changepw principal");
	goto chpwfail;
    }

    ret = krb5_rd_req(context, &auth_context, &ap_req, changepw, keytab,
		      NULL, &ticket);

    if (ret) {
	numresult = KRB5_KPASSWD_AUTHERROR;
	strcpy(strresult, "Failed reading application request");
	goto chpwfail;
    }

    /* set up address info */

    addrlen = sizeof(local_addr);

    if (getsockname(s, &local_addr, &addrlen) < 0) {
	ret = errno;
	numresult = KRB5_KPASSWD_HARDERROR;
	strcpy(strresult, "Failed getting server internet address");
	goto chpwfail;
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
	allocated_mem++;

	krb5_free_addresses(context, addrs);
    }

    addrlen = sizeof(remote_addr);

    if (getpeername(s, &remote_addr, &addrlen) < 0) {
	ret = errno;
	numresult = KRB5_KPASSWD_HARDERROR;
	strcpy(strresult, "Failed getting client internet address");
	goto chpwfail;
    }

    remote_kaddr.addrtype = ADDRTYPE_INET;
    remote_kaddr.length =
	sizeof(((struct sockaddr_in *) &remote_addr)->sin_addr);
    remote_kaddr.contents = 
	(krb5_octet *) &(((struct sockaddr_in *) &remote_addr)->sin_addr);
    
    remote_kaddr.addrtype = ADDRTYPE_INET;
    remote_kaddr.length = sizeof(sockin->sin_addr);
    remote_kaddr.contents = (krb5_octet *) &sockin->sin_addr;
    
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

    ret = krb5_auth_con_setaddrs(context, auth_context, NULL,
			     &remote_kaddr);
    if (ret) {
	numresult = KRB5_KPASSWD_HARDERROR;
	strcpy(strresult, "Failed storing client internet address");
	goto chpwfail;
    }

    /* verify that this is an AS_REQ ticket */

    if (!(ticket->enc_part2->flags & TKT_FLG_INITIAL)) {
	numresult = KRB5_KPASSWD_AUTHERROR;
	strcpy(strresult, "Ticket must be derived from a password");
	goto chpwfail;
    }

    /* construct the ap-rep */

    ret = krb5_mk_rep(context, auth_context, &ap_rep);
    if (ret) {
	numresult = KRB5_KPASSWD_AUTHERROR;
	strcpy(strresult, "Failed replying to application request");
	goto chpwfail;
    }

    /* decrypt the new password */

    cipher.length = (req->data + req->length) - ptr;
    cipher.data = ptr;

    ret = krb5_rd_priv(context, auth_context, &cipher, &clear, &replay);
    if (ret) {
	numresult = KRB5_KPASSWD_HARDERROR;
	strcpy(strresult, "Failed decrypting request");
	goto chpwfail;
    }

    ret = krb5_unparse_name(context, ticket->enc_part2->client, &clientstr);
    if (ret) {
	numresult = KRB5_KPASSWD_HARDERROR;
	strcpy(strresult, "Failed unparsing client name for log");
	goto chpwfail;
    }
    /* change the password */

    ptr = (char *) malloc(clear.length+1);
    memcpy(ptr, clear.data, clear.length);
    ptr[clear.length] = '\0';

    ret = chpass_util_wrapper(server_handle, ticket->enc_part2->client,
			      ptr, NULL, strresult, sizeof(strresult));

    /* zap the password */
    memset(clear.data, 0, clear.length);
    memset(ptr, 0, clear.length);
    krb5_xfree(clear.data);
    free(ptr);
    clear.length = 0;

    krb5_klog_syslog(LOG_NOTICE, "chpw request from %s for %s: %s",
		     inet_ntoa(((struct sockaddr_in *)&remote_addr)->sin_addr),
		     clientstr, ret ? error_message(ret) : "success");
    krb5_free_unparsed_name(context, clientstr);

    if (ret) {
	if ((ret != KADM5_PASS_Q_TOOSHORT) && 
	    (ret != KADM5_PASS_REUSE) && (ret != KADM5_PASS_Q_CLASS) && 
	    (ret != KADM5_PASS_Q_DICT) && (ret != KADM5_PASS_TOOSOON))
	    numresult = KRB5_KPASSWD_HARDERROR;
	else
	    numresult = KRB5_KPASSWD_SOFTERROR;
	/* strresult set by kadb5_chpass_principal_util() */
	goto chpwfail;
    }

    /* success! */

    numresult = KRB5_KPASSWD_SUCCESS;
    strcpy(strresult, "");

chpwfail:

    clear.length = 2 + strlen(strresult);
    clear.data = (char *) malloc(clear.length);

    ptr = clear.data;

    *ptr++ = (numresult>>8) & 0xff;
    *ptr++ = numresult & 0xff;

    memcpy(ptr, strresult, strlen(strresult));

    cipher.length = 0;

    if (ap_rep.length) {
	ret = krb5_auth_con_setaddrs(context, auth_context, &local_kaddr,
				     NULL);
	if (ret) {
	    numresult = KRB5_KPASSWD_HARDERROR;
	    strcpy(strresult,
		   "Failed storing client and server internet addresses");
	} else {
	    ret = krb5_mk_priv(context, auth_context, &clear, &cipher,
			       &replay);
	    if (ret) {
		numresult = KRB5_KPASSWD_HARDERROR;
		strcpy(strresult, "Failed encrypting reply");
	    }
	}
    }

    /* if no KRB-PRIV was constructed, then we need a KRB-ERROR.
       if this fails, just bail.  there's nothing else we can do. */

    if (cipher.length == 0) {
	/* clear out ap_rep now, so that it won't be inserted in the
           reply */

	if (ap_rep.length) {
	    krb5_xfree(ap_rep.data);
	    ap_rep.length = 0;
	}

	krberror.ctime = 0;
	krberror.cusec = 0;
	krberror.susec = 0;
	ret = krb5_timeofday(context, &krberror.stime);
	if (ret)
	    goto bailout;

	/* this is really icky.  but it's what all the other callers
	   to mk_error do. */
	krberror.error = ret;
	krberror.error -= ERROR_TABLE_BASE_krb5;
	if (krberror.error < 0 || krberror.error > 128)
	    krberror.error = KRB_ERR_GENERIC;

	krberror.client = NULL;

	ret = krb5_build_principal(context, &krberror.server,
				   strlen(realm), realm,
				   "kadmin", "changepw", NULL);
	if (ret)
	    goto bailout;
	krberror.text.length = 0;
	krberror.e_data = clear;

	ret = krb5_mk_error(context, &krberror, &cipher);

	krb5_free_principal(context, krberror.server);

	if (ret)
	    goto bailout;
    }

    /* construct the reply */

    rep->length = 6 + ap_rep.length + cipher.length;
    rep->data = (char *) malloc(rep->length);
    ptr = rep->data;

    /* length */

    *ptr++ = (rep->length>>8) & 0xff;
    *ptr++ = rep->length & 0xff;

    /* version == 0x0001 big-endian */

    *ptr++ = 0;
    *ptr++ = 1;

    /* ap_rep length, big-endian */

    *ptr++ = (ap_rep.length>>8) & 0xff;
    *ptr++ = ap_rep.length & 0xff;

    /* ap-rep data */

    if (ap_rep.length) {
	memcpy(ptr, ap_rep.data, ap_rep.length);
	ptr += ap_rep.length;
    }

    /* krb-priv or krb-error */

    memcpy(ptr, cipher.data, cipher.length);

bailout:
    if (auth_context)
	krb5_auth_con_free(context, auth_context);
    if (changepw)
	krb5_free_principal(context, changepw);
    if (ap_rep.length)
	krb5_xfree(ap_rep.data);
    if (ticket)
	krb5_free_ticket(context, ticket);
    if (clear.length)
	krb5_xfree(clear.data);
    if (cipher.length)
	krb5_xfree(cipher.data);
    if (allocated_mem) 
        krb5_xfree(local_kaddr.contents);

    return(ret);
}
