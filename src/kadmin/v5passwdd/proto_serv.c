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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
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
#include <signal.h>
#include "com_err.h"
#include "kadm5_defs.h"
#include "adm.h"
#include "adm_proto.h"
#include <setjmp.h>

static const char *proto_addrs_msg = "\004%d: cannot get memory for addresses";
static const char *proto_rcache_msg = "\004%d: cannot get replay cache";
static const char *proto_ap_req_msg = "\004%d: error reading AP_REQ message";
static const char *proto_auth_con_msg = "\004%d: cannot get authorization context";
static const char *proto_rd_req_msg = "\004%d: cannot decode AP_REQ message";
static const char *proto_mk_rep_msg = "\004%d: cannot generate AP_REP message";
static const char *proto_wr_rep_msg = "\004%d: cannot write AP_REP message";
static const char *proto_conn_abort_msg = "\007%d: connection destroyed by client";
static const char *proto_seq_err_msg = "\004%d: protocol sequence violation";
static const char *proto_rd_cmd_msg = "\004%d: cannot read administrative protocol command";
static const char *proto_db_open_msg = "\004%d: cannot open database";
static const char *proto_db_close_msg = "\004%d: cannot close database";
static const char *proto_wr_reply_msg = "\004%d: cannot write administrative protocol reply";
extern char *programname;

static int	proto_proto_timeout = -1;
static int	proto_debug_level = 0;
#if	POSIX_SETJMP
static sigjmp_buf	timeout_jmp;
#else	/* POSIX_SETJMP */
static jmp_buf		timeout_jmp;
#endif	/* POSIX_SETJMP */

static krb5_sigtype
proto_alarmclock(signo)
    int signo;
{
#if	POSIX_SETJMP
    siglongjmp(timeout_jmp, 1);
#else	/* POSIX_SETJMP */
    longjmp(timeout_jmp, 1);
#endif	/* POSIX_SETJMP */
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
    volatile krb5_error_code	kret;
    struct sockaddr_in	*cl_addr;
    struct sockaddr_in	*sv_addr;

    krb5_data		in_data;
    krb5_data		out_data;
    krb5_rcache		rcache;
    krb5_auth_context	auth_context;
    krb5_flags		ap_options;
    krb5_ticket		*ticket;
    krb5_address	*local;
    krb5_address	*remote;

#if	POSIX_SIGNALS
    struct sigaction	s_action;
#endif	/* POSIX_SIGNALS */

    char		*curr_lang = (char *) NULL;
#ifdef MIME_SUPPORTED
    krb5_boolean	mime_setting = 0;
#endif

    krb5_int32		num_args;
    krb5_data		*arglist;

    volatile krb5_boolean	db_opened;

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
    rcache = (krb5_rcache) NULL;
#if	POSIX_SIGNALS
    (void) sigemptyset(&s_action.sa_mask);
    s_action.sa_flags = 0;
#endif	/* POSIX_SIGNALS */
    db_opened = 0;

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
    kret = krb5_get_server_rcache(kcontext,
				  krb5_princ_component(kcontext,
						       net_server_princ(),
						       0),
				  &rcache);
    if (kret) {
	com_err(programname, kret, proto_rcache_msg, my_id);
	goto cleanup;
    }

    /* Initialize the auth context */
    kret = krb5_auth_con_init(kcontext, &auth_context);
    if (kret) {
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
    kret = krb5_read_message(kcontext, (krb5_pointer) &cl_sock, &in_data);
    if (kret) {
	com_err(programname, kret, proto_ap_req_msg, my_id);
	goto cleanup;
    }

    DPRINT(DEBUG_PROTO, proto_debug_level,
	   ("= %d:parse message(%d bytes)\n", my_id, in_data.length));

    /* Parse the AP_REQ message */
    kret = krb5_rd_req(kcontext, &auth_context, &in_data,
			   net_server_princ(), key_keytab_id(),
			   &ap_options, &ticket);
    if (kret) {
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
    kret = krb5_mk_rep(kcontext, auth_context, &out_data);
    if (kret) {
	com_err(programname, kret, proto_mk_rep_msg, my_id);
	goto cleanup;
    }

    DPRINT(DEBUG_PROTO, proto_debug_level,
	   ("= %d:write AP_REP(%d bytes)\n", my_id, out_data.length));
    kret = krb5_write_message(kcontext, (krb5_pointer) &cl_sock,
			      &out_data);
    if (kret) {
	com_err(programname, kret, proto_wr_rep_msg, my_id);
	goto cleanup;
    }

    /*
     * Initialization is now complete.
     *
     * If enabled, the protocol times out after proto_proto_timeout seconds.
     */
    if (
#if	POSIX_SETJMP
	sigsetjmp(timeout_jmp, 1) == 0
#else	/* POSIX_SETJMP */
	setjmp(timeout_jmp) == 0
#endif	/* POSIX_SETJMP */
	) {
	if (proto_proto_timeout > 0) {
#if	POSIX_SIGNALS
	    s_action.sa_handler = proto_alarmclock;
	    (void) sigaction(SIGALRM, &s_action, (struct sigaction *) NULL);
#else	/* POSIX_SIGNALS */
	    signal(SIGALRM, proto_alarmclock);
#endif	/* POSIX_SIGNALS */
	}
	/*
	 * Loop forever - or until somebody puts us out of our misery.
	 */
	while (1) {
	    krb5_int32	cmd_error;
	    /* If this size changed, change the sprintf below */
	    char	err_str[1024];
	    krb5_int32	cmd_repl_ncomps;
	    krb5_data	*cmd_repl_complist;
	    int		do_quit;

	    /*
	     * Read a command and figure out what to do.
	     */
	    if (proto_proto_timeout > 0)
		alarm((unsigned) proto_proto_timeout);
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
	     * First open the database.  We only have it open for the
	     * lifetime of a command so that we are sure to close it after
	     * performing an update.  This also reduces the likelihood
	     * that somebody'll have stale data lying around since we're
	     * most likely going to change something here.
	     */
	    if ((kret = key_open_db(kcontext))) {
		com_err(programname, kret, proto_db_open_msg, my_id);
		goto cleanup;
	    }
	    else
		db_opened = 1;

	    /*
	     * Now check our arguments.
	     */
	    DPRINT(DEBUG_PROTO, proto_debug_level,
		   ("= %d:parse command\n", my_id));
	    cmd_repl_ncomps = 0;
	    cmd_repl_complist = (krb5_data *) NULL;
	    if (num_args > 0) {
		if (!strcasecmp(arglist[0].data, KRB5_ADM_QUIT_CMD)) {
		    /*
		     * QUIT command handling here.
		     */
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
			strcpy(err_str,
			       "Bad argument list format for quit command.");
		    }
		}
		else if (!strcasecmp(arglist[0].data, KRB5_ADM_CHECKPW_CMD)) {
		    /*
		     * CHECKPW command handling here.
		     */
		    DPRINT(DEBUG_REQUESTS, proto_debug_level,
			   ("> %d:CHECKPW command\n", my_id));
		    if (num_args == 2) {
			DPRINT(DEBUG_REQUESTS, proto_debug_level,
			       ("> %d:CHECKPW command syntax OK\n", my_id));
			cmd_error = 0;
			err_str[0] = '\0';
#if 0
			cmd_error = pwd_check(kcontext,
					      proto_debug_level,
					      auth_context,
					      ticket,
					      &arglist[1],
					      &err_str);
#endif
		    }
		    else {
			DPRINT(DEBUG_REQUESTS, proto_debug_level,
			       ("> %d:CHECKPW command syntax BAD\n", my_id));
			cmd_error = KRB5_ADM_CMD_UNKNOWN;

			strcpy(err_str,
			       "Bad argument list format for checkpw command.");
		    }
		}
		else if (!strcasecmp(arglist[0].data, KRB5_ADM_CHANGEPW_CMD)) {
		    /*
		     * CHANGEPW command handling here.
		     */
		    DPRINT(DEBUG_REQUESTS, proto_debug_level,
			   ("> %d:CHANGEPW command\n", my_id));
		    if (num_args == 3) {
			DPRINT(DEBUG_REQUESTS, proto_debug_level,
			       ("> %d:CHANGEPW command syntax OK\n", my_id));
			cmd_error = pwd_change(kcontext,
					       proto_debug_level,
					       auth_context,
					       ticket,
					       &arglist[1],
					       &arglist[2],
					       err_str,
					       sizeof(err_str));
		    }
		    else {
			DPRINT(DEBUG_REQUESTS, proto_debug_level,
			       ("> %d:CHANGEPW command syntax BAD\n", my_id));
			cmd_error = KRB5_ADM_CMD_UNKNOWN; 
			strcpy(err_str,
			       "Bad argument list format for changepw command.");
		    }
		}
#if 0
#ifdef	MOTD_SUPPORTED
		else if (!strcasecmp(arglist[0].data, KRB5_ADM_MOTD_CMD)) {
		    /*
		     * MOTD command handling here.
		     */
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
			err_aux = KADM_BAD_ARGS;
		    }
		}
#endif	/* MOTD_SUPPORTED */
#ifdef	MIME_SUPPORTED
		else if (!strcasecmp(arglist[0].data, KRB5_ADM_MIME_CMD)) {
		    /*
		     * MIME command handling here.
		     */
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
			err_aux = KADM_BAD_ARGS;
		    }
		}
#endif	/* MIME_SUPPORTED */
#ifdef	LANGUAGES_SUPPORTED
		else if (!strcasecmp(arglist[0].data, KRB5_ADM_LANGUAGE_CMD)) {
		    /*
		     * LANGUAGE command handling here.
		     */
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
			err_aux = KADM_BAD_ARGS;
		    }
		}
#endif	/* LANGUAGES_SUPPORTED */
		else if (!strcasecmp(arglist[0].data,
				     KRB5_ADM_ADD_PRINC_CMD)) {
		    /*
		     * ADD PRINCIPAL command handling here.
		     */
		    DPRINT(DEBUG_REQUESTS, proto_debug_level,
			   ("> %d:ADD PRINCIPAL command\n", my_id));
		    /* At least one argument */
		    if (num_args > 1) {
			cmd_error = admin_add_principal(kcontext,
							proto_debug_level,
							ticket,
							num_args-1,
							&arglist[1]);
		    }
		    else {
			DPRINT(DEBUG_REQUESTS, proto_debug_level,
			       ("> %d:ADD PRINCIPAL command syntax BAD\n",
				my_id));
			cmd_error = KRB5_ADM_CMD_UNKNOWN;
			err_aux = KADM_BAD_ARGS;
		    }
		}
		else if (!strcasecmp(arglist[0].data,
				     KRB5_ADM_DEL_PRINC_CMD)) {
		    /*
		     * DELETE PRINCIPAL command handling here.
		     */
		    DPRINT(DEBUG_REQUESTS, proto_debug_level,
			   ("> %d:DELETE PRINCIPAL command\n", my_id));
		    /* Only one argument */
		    if (num_args == 2) {
			cmd_error = admin_delete_principal(kcontext,
							   proto_debug_level,
							   ticket,
							   &arglist[1]);
		    }
		    else {
			DPRINT(DEBUG_REQUESTS, proto_debug_level,
			       ("> %d:DELETE PRINCIPAL command syntax BAD\n",
				my_id));
			cmd_error = KRB5_ADM_CMD_UNKNOWN;
			err_aux = KADM_BAD_ARGS;
		    }
		}
		else if (!strcasecmp(arglist[0].data,
				     KRB5_ADM_REN_PRINC_CMD)) {
		    /*
		     * RENAME PRINCIPAL command handling here.
		     */
		    DPRINT(DEBUG_REQUESTS, proto_debug_level,
			   ("> %d:RENAME PRINCIPAL command\n", my_id));
		    /* Two arguments */
		    if (num_args == 3) {
			cmd_error = admin_rename_principal(kcontext,
							   proto_debug_level,
							   ticket,
							   &arglist[1],
							   &arglist[2]);
		    }
		    else {
			DPRINT(DEBUG_REQUESTS, proto_debug_level,
			       ("> %d:RENAME PRINCIPAL command syntax BAD\n",
				my_id));
			cmd_error = KRB5_ADM_CMD_UNKNOWN;
			err_aux = KADM_BAD_ARGS;
		    }
		}
		else if (!strcasecmp(arglist[0].data,
				     KRB5_ADM_MOD_PRINC_CMD)) {
		    /*
		     * MODIFY PRINCIPAL command handling here.
		     */
		    DPRINT(DEBUG_REQUESTS, proto_debug_level,
			   ("> %d:MODIFY PRINCIPAL command\n", my_id));
		    /* At least one argument */
		    if (num_args > 1) {
			cmd_error = admin_modify_principal(kcontext,
							   proto_debug_level,
							   ticket,
							   num_args-1,
							   &arglist[1]);
		    }
		    else {
			DPRINT(DEBUG_REQUESTS, proto_debug_level,
			       ("> %d:MODIFY PRINCIPAL command syntax BAD\n",
				my_id));
			cmd_error = KRB5_ADM_CMD_UNKNOWN;
			err_aux = KADM_BAD_ARGS;
		    }
		}
		else if (!strcasecmp(arglist[0].data,
				     KRB5_ADM_CHG_OPW_CMD)) {
		    /*
		     * CHANGE OTHER'S PASSWORD command handling here.
		     */
		    DPRINT(DEBUG_REQUESTS, proto_debug_level,
			   ("> %d:CHANGE OTHER'S PASSWORD command\n", my_id));
		    /* Two arguments */
		    if (num_args == 3) {
			cmd_error = admin_change_opwd(kcontext,
						      proto_debug_level,
						      ticket,
						      &arglist[1],
						      &arglist[2]);
		    }
		    else {
			DPRINT(DEBUG_REQUESTS, proto_debug_level,
			       ("> %d:CHANGE OTHER'S PASSWORD command syntax BAD\n",
				my_id));
			cmd_error = KRB5_ADM_CMD_UNKNOWN;
			err_aux = KADM_BAD_ARGS;
		    }
		}
		else if (!strcasecmp(arglist[0].data,
				     KRB5_ADM_CHG_ORPW_CMD)) {
		    /*
		     * CHANGE OTHER'S RANDOM PASSWORD command handling here.
		     */
		    DPRINT(DEBUG_REQUESTS, proto_debug_level,
			   ("> %d:CHANGE OTHER'S RANDOM PASSWORD command\n", my_id));
		    /* One argument */
		    if (num_args == 2) {
			cmd_error = admin_change_orandpwd(kcontext,
							  proto_debug_level,
							  ticket,
							  &arglist[1]);
		    }
		    else {
			DPRINT(DEBUG_REQUESTS, proto_debug_level,
			       ("> %d:CHANGE OTHER'S RANDOM PASSWORD command syntax BAD\n",
				my_id));
			cmd_error = KRB5_ADM_CMD_UNKNOWN;
			err_aux = KADM_BAD_ARGS;
		    }
		}
		else if (!strcasecmp(arglist[0].data,
				     KRB5_ADM_INQ_PRINC_CMD)) {
		    /*
		     * INQUIRE PRINCIPAL command handling here.
		     */
		    DPRINT(DEBUG_REQUESTS, proto_debug_level,
			   ("> %d:INQUIRE PRINCIPAL command\n", my_id));
		    /* One argument */
		    if (num_args == 2) {
			cmd_error = admin_inquire(kcontext,
						  proto_debug_level,
						  ticket,
						  &arglist[1],
						  &cmd_repl_ncomps,
						  &cmd_repl_complist);
		    }
		    else {
			DPRINT(DEBUG_REQUESTS, proto_debug_level,
			       ("> %d:INQUIRE PRINCIPAL command syntax BAD\n",
				my_id));
			cmd_error = KRB5_ADM_CMD_UNKNOWN;
			err_aux = KADM_BAD_ARGS;
		    }
		}
		else if (!strcasecmp(arglist[0].data,
				     KRB5_ADM_EXT_KEY_CMD)) {
		    /*
		     * EXTRACT KEY command handling here.
		     */
		    DPRINT(DEBUG_REQUESTS, proto_debug_level,
			   ("> %d:EXTRACT KEY command\n", my_id));
		    /* Two arguments */
		    if (num_args == 3) {
			cmd_error = admin_extract_key(kcontext,
						      proto_debug_level,
						      ticket,
						      &arglist[1],
						      &arglist[2],
						      &cmd_repl_ncomps,
						      &cmd_repl_complist);
		    }
		    else {
			DPRINT(DEBUG_REQUESTS, proto_debug_level,
			       ("> %d:EXTRACT KEY command syntax BAD\n",
				my_id));
			cmd_error = KRB5_ADM_CMD_UNKNOWN;
			err_aux = KADM_BAD_ARGS;
		    }
		}
		else if (!strcasecmp(arglist[0].data,
				     KRB5_ADM_ADD_KEY_CMD)) {
		    /*
		     * ADD KEY command handling here.
		     */
		    DPRINT(DEBUG_REQUESTS, proto_debug_level,
			   ("> %d:ADD KEY command\n", my_id));
		    /* Must have at least three arguments */
		    if (num_args > 3) {
			cmd_error = admin_add_key(kcontext,
						  proto_debug_level,
						  ticket,
						  num_args-1,
						  &arglist[1]);
		    }
		    else {
			DPRINT(DEBUG_REQUESTS, proto_debug_level,
			       ("> %d:ADD KEY command syntax BAD\n",
				my_id));
			cmd_error = KRB5_ADM_CMD_UNKNOWN;
			err_aux = KADM_BAD_ARGS;
		    }
		}
		else if (!strcasecmp(arglist[0].data,
				     KRB5_ADM_DEL_KEY_CMD)) {
		    /*
		     * DELETE KEY command handling here.
		     */
		    DPRINT(DEBUG_REQUESTS, proto_debug_level,
			   ("> %d:DELETE KEY command\n", my_id));
		    /* At least three arguments */
		    if (num_args > 3) {
			cmd_error = admin_delete_key(kcontext,
						     proto_debug_level,
						     ticket,
						     num_args-1,
						     &arglist[1]);
		    }
		    else {
			DPRINT(DEBUG_REQUESTS, proto_debug_level,
			       ("> %d:DELETE KEY command syntax BAD\n",
				my_id));
			cmd_error = KRB5_ADM_CMD_UNKNOWN;
			err_aux = KADM_BAD_ARGS;
		    }
		}
#endif /* 0 */
		else {
		    DPRINT(DEBUG_REQUESTS, proto_debug_level,
			   ("> %d:UNKNOWN command %s\n", my_id,
			  arglist[0].data));
		    cmd_error = KRB5_ADM_CMD_UNKNOWN;
		    sprintf(err_str, "Command %-.900s not supported", arglist[0].data); /* XXX Knows size of err_str.  */
		}
	    }
	    else {
		DPRINT(DEBUG_REQUESTS, proto_debug_level,
		       ("> %d:NO command!\n", my_id));
		cmd_error = KRB5_ADM_CMD_UNKNOWN;
		strcpy(err_str, "No command in message.");
	    }

	    /*
	     * Close the database.
	     */
	    if ((kret = key_close_db(kcontext))) {
		com_err(programname, kret, proto_db_close_msg, my_id);
		goto cleanup;
	    }
	    else
		db_opened = 0;

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
		krb5_data	reply_comps;

		reply_comps.data = err_str;
		reply_comps.length = strlen(err_str);
		kret = krb5_send_adm_reply(kcontext,
					   (krb5_pointer) &cl_sock,
					   auth_context,
					   cmd_error,
					   1,
					   &reply_comps);
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
	DPRINT(DEBUG_REQUESTS, proto_debug_level, ("connection timed out"));
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
	    errbuf.error = KRB5KRB_ERR_GENERIC;
	/* Format the error message in our language */
	errmsg = strdup(error_message(kret));
	errbuf.text.length = strlen(errmsg);
	errbuf.text.data = errmsg;
	er_kret = krb5_mk_error(kcontext, &errbuf, &errout);
	if (!er_kret)
	    krb5_write_message(kcontext, (krb5_pointer) &cl_sock, &errout);
	if(errmsg) free(errmsg);
	free(errbuf.text.data);
	krb5_free_data_contents(kcontext, &errout);
    }

 cleanup:
    /* If the alarm was set, make sure it's cancelled */
    if (proto_proto_timeout > 0)
	alarm(0);
    if (ticket)
	krb5_free_ticket(kcontext, ticket);
    /*
     * Don't need to close the replay cache because it's attached to the
     * auth context.
     */
    if (auth_context)
	krb5_auth_con_free(kcontext, auth_context);
    if (curr_lang)
	free(curr_lang);
    if (num_args)
	krb5_free_adm_data(kcontext, num_args, arglist);
    if (in_data.data)
	krb5_free_data_contents(kcontext, &in_data);
    if (out_data.data)
	krb5_free_data_contents(kcontext, &out_data);
    if (local && local->contents)
	free(local->contents);
    if (remote && remote->contents)
	free(remote->contents);
    if (local)
	free(local);
    if (remote)
	free(remote);
    if (db_opened)
	key_close_db(kcontext);
    close(cl_sock);

    DPRINT(DEBUG_CALLS, proto_debug_level, ("X proto_serv() = %d\n", kret));
    return(kret);
}
