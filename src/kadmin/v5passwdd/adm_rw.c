/*
 * lib/kadm/adm_rw.c
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
 * Routines to engage in the administrative (password changing) protocol.
 */
#define NEED_SOCKETS
#include "k5-int.h"
#include "adm_proto.h"

/*
 * Local prototypes (needed or else the PC will pass fail).
 */
static void kadm_copyin_int32 (char *, krb5_int32 *);
static void kadm_copyout_int32 (krb5_int32, char *);

/*
 * Routines to [de]serialize integers.
 *
 * kadm_copyin_int32	- Move a 32-bit integer fron network byte order to
 *			  host byte order.
 * kadm_copyout_int32	- Move a 32-bit integer from host byte order to
 *			  network byte order.
 */
static void
kadm_copyin_int32(cp, ip)
    char	*cp;
    krb5_int32	*ip;
{
    *ip = (((krb5_int32) ((unsigned char) cp[0]) << 24) +
	   ((krb5_int32) ((unsigned char) cp[1]) << 16) +
	   ((krb5_int32) ((unsigned char) cp[2]) << 8) +
	   ((krb5_int32) ((unsigned char) cp[3])));
}

static void
kadm_copyout_int32(outint, cp)
    krb5_int32	outint;
    char	*cp;
{
    cp[0] = (char) ((outint >> 24) & 0xff);
    cp[1] = (char) ((outint >> 16) & 0xff);
    cp[2] = (char) ((outint >> 8) & 0xff);
    cp[3] = (char) (outint & 0xff);
}

/*
 * krb5_free_adm_data()	- Free data blocks allocated by read_adm... routines.
 */
void KRB5_CALLCONV
krb5_free_adm_data(kcontext, ncomp, datap)
    krb5_context	kcontext;
    krb5_int32		ncomp;
    krb5_data		*datap;
{
    int i;
    
    if (datap) {
	for (i=0; i<ncomp; i++)
	    if (datap[i].data && (datap[i].length > 0))
		krb5_xfree(datap[i].data);

	krb5_xfree(datap);
    }
}

/*
 * krb5_send_adm_cmd()	- Send an administrative command.
 *
 * Send a list of data in a KRB_PRIV message.  Data takes the format:
 *	nargs (4 octets in network order)
 *		arg size 1 (4 octets in network order)
 *		arg data 1 ("arg size 1" octets)
 *		.
 *		.
 *		.
 */
krb5_error_code KRB5_CALLCONV
krb5_send_adm_cmd(kcontext, sock, ctx, nargs, arglist)
    krb5_context	kcontext;	/* Context handle	(In ) */
    krb5_pointer	sock;		/* Socket to write to	(In ) */
    krb5_auth_context	ctx;		/* Auth context		(In ) */
    krb5_int32			nargs;		/* Number of arguments	(In ) */
    krb5_data		*arglist;	/* Components to write	(In ) */
{
    size_t writebufsize;
    int i;
    char *writebuf;
    krb5_error_code ret;
    krb5_int32	ac_flags;

    /*
     * First check that our auth context has the right flags in it.
     */
    ret = krb5_auth_con_getflags(kcontext, ctx, &ac_flags);
    if (ret)
	return(ret);

    if ((ac_flags & (KRB5_AUTH_CONTEXT_RET_SEQUENCE|
		     KRB5_AUTH_CONTEXT_DO_SEQUENCE)) !=
	(KRB5_AUTH_CONTEXT_RET_SEQUENCE|KRB5_AUTH_CONTEXT_DO_SEQUENCE)) {
	/* XXX - need a better error */
	return(KRB5KRB_AP_ERR_MSG_TYPE);
    }

    ret = 0;
    /* Calculate write buffer size */
    writebufsize = sizeof(krb5_int32);
    for (i=0; i<nargs; i++) {
	writebufsize += sizeof(krb5_int32);	/* for argument size */
	writebufsize += arglist[i].length;	/* for actual arg */
    }

    writebuf = (char *) malloc(writebufsize);
    if (writebuf != NULL) {
	char 			*curr;
	krb5_data		write_data, out_data;
	krb5_replay_data	replay_data;

	/* Serialize into write buffer - first number of arguments */
	curr = writebuf;
	kadm_copyout_int32(nargs, curr);
	curr += sizeof(krb5_int32);

	/* Then the arguments */
	for (i=0; i<nargs; i++) {
	    kadm_copyout_int32(arglist[i].length, curr);
	    curr += sizeof(krb5_int32);
	    memcpy(curr, arglist[i].data, arglist[i].length);
	    curr += arglist[i].length;
	}

	/* Set up the message */
	write_data.length = writebufsize;
	write_data.data = writebuf;

	/* Generate the message */
	ret = krb5_mk_priv(kcontext, ctx, &write_data,
			   &out_data, &replay_data);
	if (!ret) {
	    /* Write the message */
	    ret = krb5_write_message(kcontext, sock, &out_data);
	    krb5_free_data_contents(kcontext, &out_data);
	    if (ret)
		goto cleanup;
	}

    cleanup:
	/* Paranoia */
	memset(writebuf, 0, writebufsize);
	free(writebuf);
    }
    else {
	/* error */
	ret = ENOMEM;
    }
    return(ret);
}

/*
 * krb5_send_adm_reply()	- Send an administrative reply.
 *
 * Send a reply in a KRB_PRIV message.  Data takes the format:
 *	status (4 octets in network order)
 *	ncomps (4 octets in network order)
 *		comp size 1 (4 octets in network order)
 *		comp data 1 ("comp size 1" octets)
 *		.
 *		.
 *		.
 */
krb5_error_code
krb5_send_adm_reply(kcontext, sock, ctx, cmd_stat, ncomps, complist)
    krb5_context	kcontext;	/* Context handle	(In ) */
    krb5_pointer	sock;		/* Socket to write to	(In ) */
    krb5_auth_context	ctx;		/* Auth context		(In ) */
    krb5_int32		cmd_stat;	/* Command status	(In ) */
    krb5_int32			ncomps;		/* Number of arguments	(In ) */
    krb5_data		*complist;	/* Components to write	(In ) */
{
    size_t writebufsize;
    int i;
    char *writebuf;
    krb5_error_code ret;
    krb5_int32	ac_flags;

    /*
     * First check that our auth context has the right flags in it.
     */
    ret = krb5_auth_con_getflags(kcontext, ctx, &ac_flags);
    if (ret)
	return(ret);

    if ((ac_flags & (KRB5_AUTH_CONTEXT_RET_SEQUENCE|
		     KRB5_AUTH_CONTEXT_DO_SEQUENCE)) !=
	(KRB5_AUTH_CONTEXT_RET_SEQUENCE|KRB5_AUTH_CONTEXT_DO_SEQUENCE)) {
	/* XXX - need a better error */
	return(KRB5KRB_AP_ERR_MSG_TYPE);
    }

    ret = 0;
    /* Calculate write buffer size */
    writebufsize = 2 * sizeof(krb5_int32);
    for (i=0; i<ncomps; i++) {
	writebufsize += sizeof(krb5_int32);	/* for argument size */
	writebufsize += complist[i].length;	/* for actual arg */
    }

    writebuf = (char *) malloc(writebufsize);
    if (writebuf != NULL) {
	char 			*curr;
	krb5_data		write_data, out_data;
	krb5_replay_data	replay_data;

	/* Serialize into write buffer - first command status */
	curr = writebuf;
	kadm_copyout_int32(cmd_stat, curr);
	curr += sizeof(krb5_int32);

	/* Now number of reply components */
	kadm_copyout_int32(ncomps, curr);
	curr += sizeof(krb5_int32);

	/* Then the arguments */
	for (i=0; i<ncomps; i++) {
	    kadm_copyout_int32(complist[i].length, curr);
	    curr += sizeof(krb5_int32);
	    memcpy(curr, complist[i].data, complist[i].length);
	    curr += complist[i].length;
	}

	/* Set up the message */
	write_data.length = writebufsize;
	write_data.data = writebuf;

	/* Generate the message */
	ret = krb5_mk_priv(kcontext, ctx, &write_data, &out_data, 
			   &replay_data);
	if (!ret) {
	    /* Write the message */
	    ret = krb5_write_message(kcontext, sock, &out_data);
	    krb5_free_data_contents(kcontext, &out_data);
	    if (ret)
		goto cleanup;
	}

    cleanup:
	/* Paranoia */
	memset(writebuf, 0, writebufsize);
	free(writebuf);
    }
    else {
	/* error */
	ret = ENOMEM;
    }
    return(ret);
}

/*
 * krb5_read_adm_cmd()	- Read an administrative protocol command.
 *
 * Read an administrative command from the socket.  Expect data in the
 * same format as send_adm_cmd shoots them out in.
 *
 * It is the caller's responsibility to free the memory allocated for
 * the read in argument list.
 */
krb5_error_code
krb5_read_adm_cmd(kcontext, sock, ctx, nargs, arglist)
    krb5_context	kcontext;	/* Context handle	(In ) */
    krb5_pointer	sock;		/* Socket to read from	(In ) */
    krb5_auth_context	ctx;		/* Auth context		(In ) */
    krb5_int32		*nargs;		/* Number of arguments	(Out) */
    krb5_data		**arglist;	/* List of arguments	(Out) */
{
    krb5_data		read_data;
    krb5_error_code	ret;
    krb5_data		msg_data;
    krb5_replay_data	replay_data;
    krb5_int32		ac_flags;
    krb5_int32		len32;

    /*
     * First check that our auth context has the right flags in it.
     */
    ret = krb5_auth_con_getflags(kcontext, ctx, &ac_flags);
    if (ret)
	return(ret);

    if ((ac_flags & (KRB5_AUTH_CONTEXT_RET_SEQUENCE|
		     KRB5_AUTH_CONTEXT_DO_SEQUENCE)) !=
	(KRB5_AUTH_CONTEXT_RET_SEQUENCE|KRB5_AUTH_CONTEXT_DO_SEQUENCE)) {
	/* XXX - need a better error */
	return(KRB5KRB_AP_ERR_MSG_TYPE);
    }

    if (!(ret = krb5_read_message(kcontext, sock, &read_data))) {
	if (!(ret = krb5_rd_priv(kcontext,
				 ctx,
				 &read_data,
				 &msg_data,
				 &replay_data))) {
	    char *curr;
	    int replyok;
	    int i;

	    replyok = 0;
	    /* We'd better have at least one reply component */
	    if (msg_data.length >= sizeof(krb5_int32)) {
		curr = msg_data.data;
		kadm_copyin_int32(curr, nargs);
		curr += sizeof(krb5_int32);

		/* Are there any components to copy? */
		if (*nargs > 0) {

		    /* Get the memory for the list */
		    *arglist = (krb5_data *)
			malloc((size_t) (*nargs) * sizeof(krb5_data));
		    if (*arglist != NULL) {
			krb5_data *xarglist;

			xarglist = *arglist;
			memset((char *) (xarglist), 0,
				(size_t) (*nargs) * sizeof(krb5_data));

			replyok = 1;
			/* Copy out each list entry */
			for (i=0; i<*nargs; i++) {

			    /* First get the length of the reply component */
			    if (curr + sizeof(krb5_int32) - msg_data.data <=
				msg_data.length) {

				kadm_copyin_int32(curr, &len32);
				xarglist[i].length = (int) len32;
				curr += sizeof(krb5_int32);

				/* Then get the memory for the actual data */
				if ((curr + xarglist[i].length -
				     msg_data.data <= msg_data.length) &&
				    (xarglist[i].data = (char *)
				     malloc(xarglist[i].length+1))) {

				    /* Then copy it out */
				    memcpy(xarglist[i].data,
					   curr,
					   xarglist[i].length);
				    curr += xarglist[i].length;

				    /* Null terminate for convenience */
				    xarglist[i].data[xarglist[i].length] 
					    = '\0';
				}
				else {
				    /* Not enough remaining data. */
				    replyok = 0;
				    break;
				}
			    }
			    else {
				/* Not enough remaining data */
				replyok = 0;
				break;
			    }
			}
			if (!replyok)
			    krb5_free_adm_data(kcontext, *nargs, *arglist);
		    }
		}
		else {
		    if (*nargs == 0) {
			*arglist = (krb5_data *) NULL;
			replyok = 1;
		    }
		}
	    }
	    if (!replyok) {
		ret = KRB5KRB_AP_ERR_MSG_TYPE;	/* syntax error */
	    }
	    memset(msg_data.data, 0, msg_data.length);
	    krb5_xfree(msg_data.data);
	}
	krb5_xfree(read_data.data);
    }
    return(ret);
}

/*
 * krb5_read_adm_reply()	- Read an administrative protocol response.
 *
 * Expect to read them out in the same format as send_adm_reply shoots them
 * in.
 *
 * It is the caller's responsibility to free the memory allocated for
 * the read in component list.
 */
krb5_error_code KRB5_CALLCONV
krb5_read_adm_reply(kcontext, sock, ctx, cmd_stat, ncomps, complist)
    krb5_context	kcontext;	/* Context handle	(In ) */
    krb5_pointer	sock;		/* Socket to read from	(In ) */
    krb5_auth_context	ctx;		/* Auth context		(In ) */
    krb5_int32		*cmd_stat;	/* Command status	(Out) */
    krb5_int32		*ncomps;	/* # of reply components(Out) */
    krb5_data		**complist;	/* List of components	(Out) */
{
    krb5_data		read_data;
    krb5_error_code	ret;
    krb5_data		msg_data;
    krb5_replay_data	replay_data;
    krb5_int32		ac_flags;
    krb5_int32		len32;

    /*
     * First check that our auth context has the right flags in it.
     */
    ret = krb5_auth_con_getflags(kcontext, ctx, &ac_flags);
    if (ret)
	return(ret);

    if ((ac_flags & (KRB5_AUTH_CONTEXT_RET_SEQUENCE|
		     KRB5_AUTH_CONTEXT_DO_SEQUENCE)) !=
	(KRB5_AUTH_CONTEXT_RET_SEQUENCE|KRB5_AUTH_CONTEXT_DO_SEQUENCE)) {
	/* XXX - need a better error */
	return(KRB5KRB_AP_ERR_MSG_TYPE);
    }

    if (!(ret = krb5_read_message(kcontext, sock, &read_data))) {
	if (!(ret = krb5_rd_priv(kcontext,
				 ctx,
				 &read_data,
				 &msg_data,
				 &replay_data))) {
	    char *curr;
	    int replyok;
	    int i;

	    replyok = 0;
	    /* We'd better have at least two reply components */
	    if (msg_data.length >= (2*sizeof(krb5_int32))) {
		curr = msg_data.data;
		kadm_copyin_int32(curr, cmd_stat);
		curr += sizeof(krb5_int32);
		kadm_copyin_int32(curr, ncomps);
		curr += sizeof(krb5_int32);

		/* Are there any components to copy? */
		if (*ncomps > 0) {

		    /* Get the memory for the list */
		    *complist = (krb5_data *)
			malloc((size_t) ((*ncomps) * sizeof(krb5_data)));
		    if (*complist) {
			krb5_data *xcomplist;
			
			xcomplist = *complist;
			memset((char *) (xcomplist), 0, 
			       (size_t) ((*ncomps) * sizeof(krb5_data)));
			
			replyok = 1;
			/* Copy out each list entry */
			for (i=0; i<*ncomps; i++) {

			    /* First get the length of the reply component */
			    if (curr + sizeof(krb5_int32) - msg_data.data <=
				msg_data.length) {
				kadm_copyin_int32(curr, &len32);
				xcomplist[i].length = (int) len32;
				curr += sizeof(krb5_int32);

				/* Then get the memory for the actual data */
				if ((curr + xcomplist[i].length -
				     msg_data.data <= msg_data.length) &&
				    (xcomplist[i].data = (char *)
				     malloc(xcomplist[i].length+1))) {

				    /* Then copy it out */
				    memcpy(xcomplist[i].data,
					   curr,
					   xcomplist[i].length);
				    curr += xcomplist[i].length;

				    /* Null terminate for convenience */
				    xcomplist[i].data[xcomplist[i].length] 
					    = '\0';
				}
				else {
				    /* Not enough remaining data. */
				    replyok = 0;
				    break;
				}
			    }
			    else {
				/* Not enough remaining data */
				replyok = 0;
				break;
			    }
			}
			if (!replyok)
			    krb5_free_adm_data(kcontext, *ncomps, *complist);
		    }
		}
		else {
		    if (*ncomps == 0) {
			*complist = (krb5_data *) NULL;
			replyok = 1;
		    }
		}
	    }
	    if (!replyok) {
		ret = KRB5KRB_AP_ERR_MSG_TYPE;	/* syntax error */
	    }
	    memset(msg_data.data, 0, msg_data.length);
	    krb5_xfree(msg_data.data);
	}
	krb5_xfree(read_data.data);
    }
    return(ret);
}
