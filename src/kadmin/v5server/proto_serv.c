/*
 * kadmin/v5server/proto_serv.c
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
 * proto_serv.c - Engage in protocol.  This module reflects the connection
 * 	protocol as implemented in lib/krb5/os/adm_conn.c.  Any changes
 *	in one module must be reflected in the other.
 */
#define	NEED_SOCKETS
#include "k5-int.h"
#include "com_err.h"
#include "kadm5_defs.h"
#include "adm.h"
#include <setjmp.h>

static const char *proto_addrs_msg = "%d: cannot get memory for addresses";
static const char *proto_rcache_msg = "%d: cannot get replay cache";
static const char *proto_ap_req_msg = "%d: error reading AP_REQ message";
static const char *proto_auth_con_msg = "%d: cannot get authorization context";
static const char *proto_rd_req_msg = "%d: cannot decode AP_REQ message";
static const char *proto_mk_rep_msg = "%d: cannot generate AP_REP message";
static const char *proto_wr_rep_msg = "%d: cannot write AP_REP message";
static const char *proto_conn_abort_msg = "%d: connection destroyed by client";
static const char *proto_seq_err_msg = "%d: protocol sequence violation";
static const char *proto_rd_cmd_msg = "%d: cannot read administrative protocol command";
static const char *proto_wr_reply_msg = "%d: cannot write administrative protocol reply";
static const char *proto_fmt_reply_msg = "%d: cannot format administrative protocol reply";
extern char *programname;

static int	proto_proto_timeout = -1;
static int	proto_debug_level = 0;
static jmp_buf	timeout_jmp;

static krb5_sigtype
proto_alarmclock()
{
    longjmp(timeout_jmp, 1);
    /* NOTREACHED */
}

krb5_error_code
proto_init(kcontext, debug_level, timeo)
    krb5_context	kcontext;
    int			debug_level;
    int			timeo;
{
    krb5_error_code	kret;

    proto_debug_level = debug_level;
    DPRINT(DEBUG_CALLS, proto_debug_level,
	   ("* proto_init(timeo=%d)\n", timeo));
    kret = 0;
    proto_proto_timeout = timeo;
    DPRINT(DEBUG_CALLS, proto_debug_level, ("X proto_init() = %d\n", kret));
    return(kret);
}

void
proto_finish(kcontext, debug_level)
    krb5_context	kcontext;
    int			debug_level;
{
    DPRINT(DEBUG_CALLS, proto_debug_level, ("* proto_finish()\n"));
    DPRINT(DEBUG_CALLS, proto_debug_level, ("X proto_finish()\n"));
}

krb5_error_code
proto_serv(kcontext, my_id, cl_sock, sv_p, cl_p)
    krb5_context	kcontext;
    krb5_int32		my_id;
    int			cl_sock;
    void		*sv_p;
    void		*cl_p;
{
    krb5_error_code	kret;
    struct sockaddr_in	*cl_addr;
    struct sockaddr_in	*sv_addr;

    krb5_data		in_data;
    krb5_data		out_data;
    krb5_rcache		rcache;
    krb5_auth_context	*auth_context;
    krb5_flags		ap_options;
    krb5_ticket		*ticket;
    krb5_address	*local;
    krb5_address	*remote;

    char		*curr_lang = (char *) NULL;
    krb5_boolean	mime_setting = 0;

    krb5_int32		num_args;
    krb5_data		*arglist;

    cl_addr = (struct sockaddr_in *) cl_p;
    sv_addr = (struct sockaddr_in *) sv_p;
    DPRINT(DEBUG_CALLS, proto_debug_level,
	   ("* proto_serv(id=%d, sock=%d, local=%x, remote=%x)\n",
	    my_id, cl_sock,
	    ntohl(sv_addr->sin_addr.s_addr),
	    ntohl(cl_addr->sin_addr.s_addr)));

    /* Initialize */
    memset((char *) &in_data, 0, sizeof(in_data));
    memset((char *) &out_data, 0, sizeof(out_data));
    num_args = 0;
    local = (krb5_address *) NULL;
    remote = (krb5_address *) NULL;
    ticket = (krb5_ticket *) NULL;

    /* Get memory for addresses */
    local = (krb5_address *) malloc(sizeof(krb5_address));
    remote = (krb5_address *) malloc(sizeof(krb5_address));
    if (!local || !remote) {
	kret = ENOMEM;
	com_err(programname, kret, proto_addrs_msg, my_id);
	goto cleanup;
    }

    local->contents = (krb5_octet *) malloc(sizeof(struct in_addr));
    remote->contents = (krb5_octet *) malloc(sizeof(struct in_addr));
    if (!local->contents || !remote->contents) {
	kret = ENOMEM;
	com_err(programname, kret, proto_addrs_msg, my_id);
	goto cleanup;
    }

    /*
     * First setup the replay cache.
     */
    if (kret = krb5_get_server_rcache(kcontext,
				      krb5_princ_component(kcontext,
							   net_server_princ(),
							   0),
				      &rcache)) {
	com_err(programname, kret, proto_rcache_msg, my_id);
	goto cleanup;
    }

    /* Initialize the auth context */
    if (kret = krb5_auth_con_init(kcontext, &auth_context)) {
	com_err(programname, kret, proto_auth_con_msg, my_id);
	goto cleanup;
    }

    krb5_auth_con_setrcache(kcontext, auth_context, rcache);

    /*
     * Set up addresses.
     */
    local->addrtype = remote->addrtype = ADDRTYPE_INET;
    local->length = remote->length = sizeof(struct in_addr);
    memcpy((char *) local->contents,
	   (char *) &sv_addr->sin_addr,
	   sizeof(struct in_addr));
    memcpy((char *) remote->contents,
	   (char *) &cl_addr->sin_addr,
	   sizeof(struct in_addr));
    krb5_auth_con_setflags(kcontext, auth_context,
			   KRB5_AUTH_CONTEXT_RET_SEQUENCE|
			   KRB5_AUTH_CONTEXT_DO_SEQUENCE);
    krb5_auth_con_setaddrs(kcontext, auth_context, local, remote);

    DPRINT(DEBUG_PROTO, proto_debug_level,
	   ("= %d:read message(local=%x, remote=%x)\n",
	    my_id,
	    ntohl(sv_addr->sin_addr.s_addr),
	    ntohl(cl_addr->sin_addr.s_addr)));
    /* Now, read in the AP_REQ message and decode it. */
    if (kret = krb5_read_message(kcontext,
				 (krb5_pointer) &cl_sock,
				 &in_data)) {
	com_err(programname, kret, proto_ap_req_msg, my_id);
	goto cleanup;
    }

    DPRINT(DEBUG_PROTO, proto_debug_level,
	   ("= %d:parse message(%d bytes)\n", my_id, in_data.length));
    /* Parse the AP_REQ message */
    if (kret = krb5_rd_req(kcontext,
			   &auth_context,
			   &in_data,
			   net_server_princ(),
			   (krb5_keytab) NULL,
			   &ap_options,
			   &ticket)) {
	com_err(programname, kret, proto_rd_req_msg, my_id);
	goto err_reply;
    }

    DPRINT(DEBUG_PROTO, proto_debug_level,
	   ("= %d:check AP_REQ(options are %x)\n", my_id, ap_options));
    /* Check our options */
    if ((ap_options & AP_OPTS_MUTUAL_REQUIRED) == 0) {
	kret = KRB5KRB_AP_ERR_MSG_TYPE;
	goto err_reply;
    }

    DPRINT(DEBUG_PROTO, proto_debug_level,
	   ("= %d:make AP_REP\n", my_id));
    if (kret = krb5_mk_rep(kcontext, auth_context, &out_data)) {
	com_err(programname, kret, proto_mk_rep_msg, my_id);
	goto cleanup;
    }

    DPRINT(DEBUG_PROTO, proto_debug_level,
	   ("= %d:write AP_REP(%d bytes)\n", my_id, out_data.length));
    if (kret = krb5_write_message(kcontext,
				  (krb5_pointer) &cl_sock,
				  &out_data)) {
	com_err(programname, kret, proto_wr_rep_msg, my_id);
	goto cleanup;
    }

    /*
     * Initialization is now complete.
     *
     * If enabled, the protocol times out after proto_proto_timeout seconds.
     */
    if (setjmp(timeout_jmp) == 0) {
	if (proto_proto_timeout > 0) {
	    signal(SIGALRM, proto_alarmclock);
	}
	/*
	 * Loop forever - or until somebody puts us out of our misery.
	 */
	while (1) {
	    krb5_int32	cmd_error;
	    krb5_int32	err_aux;
	    krb5_int32	cmd_repl_ncomps;
	    krb5_data	*cmd_repl_complist;
	    int		do_quit;

	    /*
	     * Read a command and figure out what to do.
	     */
	    if (proto_proto_timeout > 0)
		alarm(proto_proto_timeout);
	    num_args = 0;
	    DPRINT(DEBUG_PROTO, proto_debug_level,
		   ("= %d:waiting for command\n", my_id));
	    kret = krb5_read_adm_cmd(kcontext,
				     (krb5_pointer) &cl_sock,
				     auth_context,
				     &num_args,
				     &arglist);
	    if (proto_proto_timeout > 0)
		alarm(0);
	    if (kret) {
		/*
		 * It's OK to have connections abort here.
		 */
		if (kret == ECONNABORTED) {
		    com_err(programname, kret, proto_conn_abort_msg, my_id);
		    kret = 0;
		}
		else if (kret == KRB5KRB_AP_ERR_BADORDER) {
		    com_err(programname, kret, proto_seq_err_msg, my_id);
		    kret = 0;
		}
		else
		    com_err(programname, kret, proto_rd_cmd_msg, my_id);
		goto cleanup;
	    }

	    cmd_error = KRB5_ADM_SUCCESS;
	    do_quit = 0;

	    /*
	     * Now check our arguments.
	     */
	    DPRINT(DEBUG_PROTO, proto_debug_level,
		   ("= %d:parse command\n", my_id));
	    cmd_repl_ncomps = 0;
	    cmd_repl_complist = (krb5_data *) NULL;
	    err_aux = 0;
	    if (num_args > 0) {
		if (!strcasecmp(arglist[0].data, KRB5_ADM_QUIT_CMD)) {
		    DPRINT(DEBUG_REQUESTS, proto_debug_level,
			   ("> %d:QUIT command\n", my_id));
		    /* QUIT takes no arguments */
		    if (num_args == 1) {
			DPRINT(DEBUG_REQUESTS, proto_debug_level,
			       ("> %d:QUIT command syntax OK\n", my_id));
			do_quit = 1;
		    }
		    else {
			DPRINT(DEBUG_REQUESTS, proto_debug_level,
			       ("> %d:QUIT command syntax BAD\n", my_id));
			cmd_error = KRB5_ADM_CMD_UNKNOWN;
			err_aux = KRB5_ADM_BAD_ARGS;
		    }
		}
		else if (!strcasecmp(arglist[0].data, KRB5_ADM_CHECKPW_CMD)) {
		    DPRINT(DEBUG_REQUESTS, proto_debug_level,
			   ("> %d:CHECKPW command\n", my_id));
		    if (num_args == 2) {
			DPRINT(DEBUG_REQUESTS, proto_debug_level,
			       ("> %d:CHECKPW command syntax OK\n", my_id));
			cmd_error = passwd_check(kcontext,
						 proto_debug_level,
						 auth_context,
						 ticket,
						 &arglist[1],
						 &err_aux);
		    }
		    else {
			DPRINT(DEBUG_REQUESTS, proto_debug_level,
			       ("> %d:CHECKPW command syntax BAD\n", my_id));
			cmd_error = KRB5_ADM_CMD_UNKNOWN;
			err_aux = KRB5_ADM_BAD_ARGS;
		    }
		}
		else if (!strcasecmp(arglist[0].data, KRB5_ADM_CHANGEPW_CMD)) {
		    DPRINT(DEBUG_REQUESTS, proto_debug_level,
			   ("> %d:CHANGEPW command\n", my_id));
		    if (num_args == 3) {
			DPRINT(DEBUG_REQUESTS, proto_debug_level,
			       ("> %d:CHANGEPW command syntax OK\n", my_id));
			cmd_error = passwd_change(kcontext,
						  proto_debug_level,
						  auth_context,
						  ticket,
						  &arglist[1],
						  &arglist[2],
						  &err_aux);
		    }
		    else {
			DPRINT(DEBUG_REQUESTS, proto_debug_level,
			       ("> %d:CHANGEPW command syntax BAD\n", my_id));
			cmd_error = KRB5_ADM_CMD_UNKNOWN; 
			err_aux = KRB5_ADM_BAD_ARGS;
		    }
		}
		else if (!strcasecmp(arglist[0].data, KRB5_ADM_MOTD_CMD)) {
		    DPRINT(DEBUG_REQUESTS, proto_debug_level,
			   ("> %d:MOTD command\n", my_id));
		    if (num_args <= 2) {
			DPRINT(DEBUG_REQUESTS, proto_debug_level,
			       ("> %d:MOTD command syntax OK\n", my_id));
			printf("@@@ motd command ");
			if (num_args == 2)
			    printf("context is %s", arglist[2].data);
			printf("\n");
		    }
		    else {
			DPRINT(DEBUG_REQUESTS, proto_debug_level,
			       ("> %d:MOTD command syntax BAD\n", my_id));
			cmd_error = KRB5_ADM_CMD_UNKNOWN;
			err_aux = KRB5_ADM_BAD_ARGS;
		    }
		}
		else if (!strcasecmp(arglist[0].data, KRB5_ADM_MIME_CMD)) {
		    DPRINT(DEBUG_REQUESTS, proto_debug_level,
			   ("> %d:MIME command\n", my_id));
		    if (num_args == 1) {
			DPRINT(DEBUG_REQUESTS, proto_debug_level,
			       ("> %d:MIME command syntax OK\n", my_id));
			mime_setting = 1;
		    }
		    else {
			DPRINT(DEBUG_REQUESTS, proto_debug_level,
			       ("> %d:MIME command syntax BAD\n", my_id));
			cmd_error = KRB5_ADM_CMD_UNKNOWN;
			err_aux = KRB5_ADM_BAD_ARGS;
		    }
		}
		else if (!strcasecmp(arglist[0].data, KRB5_ADM_LANGUAGE_CMD)) {
		    DPRINT(DEBUG_REQUESTS, proto_debug_level,
			   ("> %d:LANGUAGE command\n", my_id));
		    if (num_args == 2) {
			DPRINT(DEBUG_REQUESTS, proto_debug_level,
			       ("> %d:LANGUAGE command syntax OK\n", my_id));
			if (output_lang_supported(arglist[1].data)) {
			    if (curr_lang)
				free(curr_lang);
			    curr_lang = (char *)
				malloc(strlen(arglist[1].data));
			    if (curr_lang)
				strcpy(curr_lang, arglist[1].data);
			}
			else
			    cmd_error = KRB5_ADM_LANG_NOT_SUPPORTED;
		    }
		    else {
			DPRINT(DEBUG_REQUESTS, proto_debug_level,
			       ("> %d:LANGUAGE command syntax BAD\n", my_id));
			cmd_error = KRB5_ADM_CMD_UNKNOWN;
			err_aux = KRB5_ADM_BAD_ARGS;
		    }
		}
		else {
		    DPRINT(DEBUG_REQUESTS, proto_debug_level,
			   ("> %d:UNKNOWN command %s\n", my_id,
			  arglist[0].data));
		    cmd_error = KRB5_ADM_CMD_UNKNOWN;
		    err_aux = KRB5_ADM_BAD_CMD;
		}
	    }
	    else {
		DPRINT(DEBUG_REQUESTS, proto_debug_level,
		       ("> %d:NO command!\n", my_id));
		cmd_error = KRB5_ADM_CMD_UNKNOWN;
		err_aux = KRB5_ADM_NO_CMD;
	    }

	    /*
	     * Now make the reply.
	     */
	    DPRINT(DEBUG_PROTO, proto_debug_level,
		   ("= %d:sending reply(stat=%d)\n", my_id, cmd_error));
	    if (cmd_error == KRB5_ADM_SUCCESS) {
		kret = krb5_send_adm_reply(kcontext,
					   (krb5_pointer) &cl_sock,
					   auth_context,
					   cmd_error,
					   cmd_repl_ncomps,
					   cmd_repl_complist);
		if (kret) {
		    com_err(programname, kret, proto_wr_reply_msg, my_id);
		    goto cleanup;
		}
	    }
	    else {
		char		*adm_errmsg;
		krb5_data	reply_comps;

		adm_errmsg =  output_adm_error(curr_lang,
					       mime_setting,
					       cmd_error,
					       err_aux,
					       num_args,
					       arglist);
		if (!adm_errmsg) {
		    com_err(programname, kret, proto_fmt_reply_msg, my_id);
		    goto cleanup;
		}
		reply_comps.data = adm_errmsg;
		reply_comps.length = strlen(adm_errmsg);
		kret = krb5_send_adm_reply(kcontext,
					   (krb5_pointer) &cl_sock,
					   auth_context,
					   cmd_error,
					   1,
					   &reply_comps);
		free(adm_errmsg);
		if (kret) {
		    com_err(programname, kret, proto_wr_reply_msg, my_id);
		    goto cleanup;
		}
	    }
	    if (cmd_repl_ncomps > 0)
		krb5_free_adm_data(kcontext,
				   cmd_repl_ncomps,
				   cmd_repl_complist);

	    if (do_quit)
		break;
	    krb5_free_adm_data(kcontext, num_args, arglist);
	}
    }
    else {
	DLOG(DEBUG_REQUESTS, proto_debug_level, "connection timed out");
    }

    
 err_reply:
    if (kret) {
	krb5_error_code	er_kret;
	krb5_error	errbuf;
	char		*errmsg;
	krb5_data	errout;

	memset((char *) &errbuf, 0, sizeof(errbuf));
	krb5_us_timeofday(kcontext, &errbuf.stime, &errbuf.susec);
	errbuf.server = net_server_princ();
	errbuf.error = kret - ERROR_TABLE_BASE_krb5;
	if (errbuf.error > 127)
	    errbuf.error = KRB_ERR_GENERIC;
	/* Format the error message in our language */
	errmsg = output_krb5_errmsg(curr_lang, mime_setting, kret);
	errbuf.text.length = strlen(errmsg);
	errbuf.text.data = errmsg;
	er_kret = krb5_mk_error(kcontext, &errbuf, &errout);
	if (!er_kret)
	    krb5_write_message(kcontext, (krb5_pointer) &cl_sock, &errout);
	free(errbuf.text.data);
	krb5_xfree(errout.data);
    }

 cleanup:
    /* If the alarm was set, make sure it's cancelled */
    if (proto_proto_timeout > 0)
	alarm(0);
    if (ticket)
	krb5_free_ticket(kcontext, ticket);
    if (rcache)
	krb5_rc_close(kcontext, rcache);
    if (auth_context)
	krb5_xfree(auth_context);
    if (curr_lang)
	free(curr_lang);
    if (num_args)
	krb5_free_adm_data(kcontext, num_args, arglist);
    if (in_data.data)
	krb5_xfree(in_data.data);
    if (out_data.data)
	krb5_xfree(out_data.data);
    if (local && local->contents)
	free(local->contents);
    if (remote && remote->contents)
	free(remote->contents);
    if (local)
	free(local);
    if (remote)
	free(remote);
    close(cl_sock);

 done:
    DPRINT(DEBUG_CALLS, proto_debug_level, ("X proto_serv() = %d\n", kret));
    return(kret);
}
