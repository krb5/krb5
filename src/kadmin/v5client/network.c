/*
 * kadmin/v5client/network.c
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
 * network.c	- Handle network and protocol related functions for kadmin5.
 */
#include "k5-int.h"
#include "com_err.h"
#include "adm.h"
#include "adm_proto.h"
#include "kadmin5.h"

/*
 * Own storage.
 */
static int		server_socket = -1;
static krb5_auth_context server_auth_context = (krb5_auth_context) NULL;
static krb5_ccache	server_ccache = (krb5_ccache) NULL;
static krb5_boolean	server_active = 0;
static krb5_error_code	server_stat = 0;
static krb5_boolean	server_op_in_prog = 0;

/*
 * Static strings.
 */
static const char *kadmin_server_name	= "kadmin-server";
static const char *proto_serv_supp_msg	= "server response follows:";
static const char *proto_serv_end_msg	= "end of server response.";
static const char *proto_cmd_unsupp_fmt	= "(%s) %s protocol command not supported by server";
static const char *proto_pw_unacc_fmt	= "(%s) password unacceptable to server";
static const char *proto_bad_pw_fmt	= "(%s) bad password entered";
static const char *proto_in_tkt_fmt	= "(%s) not an initial ticket";
static const char *proto_cant_chg_fmt	= "(%s) cannot change password";
static const char *proto_lang_uns_fmt	= "(%s) language not supported";
static const char *proto_p_exists_fmt	= "(%s) principal already exists";
static const char *proto_p_notexist_fmt	= "(%s) principal does not exist";
static const char *proto_no_auth_fmt	= "(%s) not authorized for this operation";
static const char *proto_bad_opt_fmt	= "(%s) option not recognized by server";
static const char *proto_value_req_fmt	= "(%s) value required for option";
static const char *proto_system_err_fmt	= "(%s) remote system error";
static const char *proto_key_exists_fmt	= "(%s) key/salt type already present";
static const char *proto_key_ufo_fmt	= "(%s) key/salt type not present";
static const char *proto_ufo_err_fmt	= "- (%s) protocol command %s returned unexpected error %d";
static const char *net_conn_err_fmt	= "- %s: cannot connect to server";
static const char *net_ccache_fmt	= "- cannot find credential cache %s";

/*
 * print_proto_sreply()	- Print server's error reply strings.
 */
void
print_proto_sreply(ncomps, complist)
    krb5_int32	ncomps;
    krb5_data	*complist;
{
    int i;

    if (ncomps > 0) {
	for (i=0; i<ncomps; i++)
	    com_err(kadmin_server_name, 0, complist[i].data);
    }
}

/*
 * print_proto_error()	- Print protocol error message if appropriate.
 */
void
print_proto_error(cmd, cstat, ncomps, complist)
    char	*cmd;
    krb5_int32	cstat;
    krb5_int32	ncomps;
    krb5_data	*complist;
{
    switch (cstat) {
    case KRB5_ADM_SUCCESS:
	break;
    case KRB5_ADM_CMD_UNKNOWN:
	com_err(programname, 0, proto_cmd_unsupp_fmt, requestname, cmd);
	break;
    case KRB5_ADM_PW_UNACCEPT:
	com_err(programname, 0, proto_pw_unacc_fmt, requestname);
	break;
    case KRB5_ADM_BAD_PW:
	com_err(programname, 0, proto_bad_pw_fmt, requestname);
	break;
    case KRB5_ADM_NOT_IN_TKT:
	com_err(programname, 0, proto_in_tkt_fmt, requestname);
	break;
    case KRB5_ADM_CANT_CHANGE:
	com_err(programname, 0, proto_cant_chg_fmt, requestname);
	break;
    case KRB5_ADM_LANG_NOT_SUPPORTED:
	com_err(programname, 0, proto_lang_uns_fmt, requestname);
	break;
    case KRB5_ADM_P_ALREADY_EXISTS:
	com_err(programname, 0, proto_p_exists_fmt, requestname);
	break;
    case KRB5_ADM_P_DOES_NOT_EXIST:
	com_err(programname, 0, proto_p_notexist_fmt, requestname);
	break;
    case KRB5_ADM_NOT_AUTHORIZED:
	com_err(programname, 0, proto_no_auth_fmt, requestname);
	break;
    case KRB5_ADM_BAD_OPTION:
	com_err(programname, 0, proto_bad_opt_fmt, requestname);
	break;
    case KRB5_ADM_VALUE_REQUIRED:
	com_err(programname, 0, proto_value_req_fmt, requestname);
	break;
    case KRB5_ADM_SYSTEM_ERROR:
	com_err(programname, 0, proto_system_err_fmt, requestname);
	break;
    case KRB5_ADM_KEY_ALREADY_EXISTS:
	com_err(programname, 0, proto_key_exists_fmt, requestname);
	break;
    case KRB5_ADM_KEY_DOES_NOT_EXIST:
	com_err(programname, 0, proto_key_ufo_fmt, requestname);
	break;
    default:
	com_err(programname, cstat, proto_ufo_err_fmt, requestname,
		cmd, cstat);
	break;
    }
    if (cstat != KRB5_ADM_SUCCESS)
	print_proto_sreply(ncomps, complist);
}

/*
 * net_connect()	- Connect to the administrative server if not already
 *			  connected or a separate connection is required for
 *			  each transaction.
 */
krb5_error_code
net_connect()
{
    krb5_error_code	kret = 0;

    /*
     * Drop the connection if we were in the middle of something before.
     */
    if (server_op_in_prog)
	net_disconnect(1);

    if (!multiple || !server_active) {
	char opassword[KRB5_ADM_MAX_PASSWORD_LEN];

	/* Resolve ccache name if supplied. */
	if (ccname2use) {
	    if (kret = krb5_cc_resolve(kcontext, ccname2use, &server_ccache)) {
		com_err(programname, kret, net_ccache_fmt, ccname2use);
		return(kret);
	    }
	}
	else
	    server_ccache = (krb5_ccache) NULL;

	if (!(kret = server_stat = krb5_adm_connect(kcontext,
						    principal_name,
						    password_prompt,
						    opassword,
						    &server_socket,
						    &server_auth_context,
						    &server_ccache,
						    ccname2use,
						    ticket_life))) {
	    server_active = 1;
	    memset(opassword, 0, KRB5_ADM_MAX_PASSWORD_LEN);
	}
	else
	    com_err(programname, kret, net_conn_err_fmt, requestname);
    }
    return(kret);
}

/*
 * net_disconnect()	- Disconnect from the server.  If there has been
 *			  a server error, just close the socket.  Otherwise
 *			  engage in the disconnection protocol.
 */
void
net_disconnect(force)
    krb5_boolean	force;
{
    /*
     * Only need to do this if we think the connection is active.
     */
    if (server_active) {
	/*
	 * Disconnect if:
	 *	1) this is a one-time-only connection.
	 *	2) there was an error on the connection.
	 *	3) somebody's forcing the disconnection.
	 */
	if (!multiple || (server_stat != 0) || force) {
	    /* If the connection is still good, then send a QUIT command */
	    if ((server_stat == 0) && !server_op_in_prog) {
		krb5_data	quit_data;
		krb5_int32	quit_status;
		krb5_int32	quit_ncomps;
		krb5_data	*quit_reply;

		quit_data.data = KRB5_ADM_QUIT_CMD;
		quit_data.length = strlen(quit_data.data);
		if (!(server_stat = krb5_send_adm_cmd(kcontext,
						      &server_socket,
						      server_auth_context,
						      1,
						      &quit_data)))
		    server_stat = krb5_read_adm_reply(kcontext,
						      &server_socket,
						      server_auth_context,
						      &quit_status,
						      &quit_ncomps,
						      &quit_reply);
		if (!server_stat) {
		    print_proto_error(KRB5_ADM_QUIT_CMD,
				      quit_status,
				      quit_ncomps,
				      quit_reply);
		    krb5_free_adm_data(kcontext, quit_ncomps, quit_reply);
		}
	    }
	    /* Break down the connection */
	    krb5_adm_disconnect(kcontext,
				&server_socket,
				server_auth_context,
				(delete_ccache) ? server_ccache :
					(krb5_ccache) NULL);
	    if (!delete_ccache)
		krb5_cc_close(kcontext, server_ccache);

	    /* Clean up our state. */
	    server_socket = -1;
	    server_auth_context = (krb5_auth_context) NULL;
	    server_ccache = (krb5_ccache) NULL;
	    server_active = 0;
	    server_op_in_prog = 0;
	    server_stat = EINVAL;
	}
    }
}

/*
 * net_do_proto()	- Perform a protocol request and return the results.
 */
krb5_error_code
net_do_proto(cmd, arg1, arg2, nargs, argp, rstatp, ncompp, complistp, caller)
    char	*cmd;
    char	*arg1;
    char	*arg2;
    krb5_int32	nargs;
    krb5_data	*argp;
    krb5_int32	*rstatp;
    krb5_int32	*ncompp;
    krb5_data	**complistp;
    krb5_boolean caller;
{
    krb5_error_code	kret;
    krb5_int32		nprotoargs;
    krb5_data		*protoargs;

    /* Connect to the server, if necessary */
    if (caller || !(kret = net_connect())) {

	/* Figure out how many things we need to prepend to the arguments */
	nprotoargs = nargs + 1;
	if (arg1)
	    nprotoargs++;
	if (arg2)
	    nprotoargs++;

	/* Get the space for the new argument list */
	if (protoargs = (krb5_data *) malloc((size_t) nprotoargs *
					     sizeof(krb5_data))) {
	    int	index = 0;

	    /* Copy in the command */
	    protoargs[index].data = cmd;
	    protoargs[index].length = strlen(cmd);
	    index++;

	    /* Copy in the optional arguments */
	    if (arg1) {
		protoargs[index].data = arg1;
		protoargs[index].length = strlen(arg1);
		index++;
	    }
	    if (arg2) {
		protoargs[index].data = arg2;
		protoargs[index].length = strlen(arg2);
		index++;
	    }

	    /* Copy in the argument list */
	    memcpy(&protoargs[index], argp,
		   (size_t) (nargs*sizeof(krb5_data)));

	    server_op_in_prog = 1;
	    /*
	     * Now send the command.
	     */
	    if (!(kret = server_stat = krb5_send_adm_cmd(kcontext,
							 &server_socket,
							 server_auth_context,
							 nprotoargs,
							 protoargs))) {
		/*
		 * If that was successful, then try to read the reply.
		 */
		kret = server_stat = krb5_read_adm_reply(kcontext,
							 &server_socket,
							 server_auth_context,
							 rstatp,
							 ncompp,
							 complistp);
		print_proto_error(cmd, *rstatp, *ncompp, *complistp);
	    }
	    server_op_in_prog = 0;
	    free(protoargs);
	}
	else
	    kret = ENOMEM;
	if (!caller)
	    net_disconnect(0);
    }
    return(kret);
}
