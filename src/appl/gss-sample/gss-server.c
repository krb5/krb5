/*
 * Copyright 1994 by OpenVision Technologies, Inc.
 * 
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of OpenVision not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission. OpenVision makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 * 
 * OPENVISION DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL OPENVISION BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/time.h>
#include <time.h>

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_generic.h>

#ifdef USE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

int create_socket();

int send_token();
int recv_token();
void display_status();

extern FILE *display_file;
FILE *log;


void
usage()
{
     fprintf(stderr, "Usage: gss-server [-port port] [-v2] [-inetd] [-logfile file] service_name\n");
     exit(1);
}

int
main(argc, argv)
     int argc;
     char **argv;
{
     char *service_name;
     u_short port = 4444;
     int s;
     int do_inetd = 0;
     int dov2 = 0;
     int once = 0;

     log = stdout;
     argc--; argv++;
     while (argc) {
	  if (strcmp(*argv, "-port") == 0) {
	       argc--; argv++;
	       if (!argc) usage();
	       port = atoi(*argv);
	  } else if (strcmp(*argv, "-inetd") == 0) {
	      do_inetd = 1;
	  } else if (strcmp(*argv, "-v2") == 0) {
	      dov2 = 1;
	  } else if (strcmp(*argv, "-once") == 0) {
	      once = 1;
	  } else if (strcmp(*argv, "-logfile") == 0) {
	      argc--; argv++;
	      if (!argc) usage();
	      log = fopen(*argv, "a");
	      display_file = log;
	      if (!log) {
		  perror(*argv);
		  exit(1);
	      }
	  } else
	       break;
	  argc--; argv++;
     }
     if (argc != 1)
	  usage();

     service_name = *argv;

     if (do_inetd == 0) {
	 if ((s = create_socket(port)) < 0)
	     exit(1);
     } else {
	 s = -1;
	 close(1);
	 close(2);
     }

     if (sign_server(s, service_name, dov2, once) < 0)
	  exit(1);
     
     /*NOTREACHED*/
     return 0;
}

/*
 * Function: create_socket
 *
 * Purpose: Opens a listening TCP socket.
 *
 * Arguments:
 *
 * 	port		(r) the port number on which to listen
 *
 * Returns: the listening socket file descriptor, or -1 on failure
 *
 * Effects:
 *
 * A listening socket on the specified port and created and returned.
 * On error, an error message is displayed and -1 is returned.
 */
int create_socket(port)
     u_short port;
{
     struct sockaddr_in saddr;
     int s;
     int on = 1;
     
     saddr.sin_family = AF_INET;
     saddr.sin_port = htons(port);
     saddr.sin_addr.s_addr = INADDR_ANY;

     if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
	  perror("creating socket");
	  return -1;
     }
     /* Let the socket be reused right away */
     (void) setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on));
     if (bind(s, (struct sockaddr *) &saddr, sizeof(saddr)) < 0) {
	  perror("binding socket");
	  return -1;
     }
     if (listen(s, 5) < 0) {
	  perror("listening on socket");
	  return -1;
     }
     return s;
}

/*
 * Function: sign_server
 *
 * Purpose: Performs the "sign" service.
 *
 * Arguments:
 *
 * 	s		(r) a TCP socket on which to listen for connections.
 * 			If s is -1, then assume that we were started out of 
 * 			inetd and use file descriptor 0.
 * 	service_name	(r) the ASCII name of the GSS-API service to
 * 			establish a context as
 *	dov2		(r) a boolean indicating whether we should use GSSAPI
 *			V2 interfaces, if available.
 *	once		(r) a boolean indicating whether we should
 * 			only accept one connection, then exit.
 * 
 * Returns: -1 on error
 *
 * Effects:
 *
 * sign_server acquires GSS-API credentials for service_name and then
 * loops forever accepting TCP connections on s, establishing a
 * context, and performing a single sign request.
 *
 * A sign request is a single GSS-API sealed token.  The token is
 * unsealed and a signature block, produced with gss_sign, is returned
 * to the sender.  The context is the destroyed and the connection
 * closed.
 *
 * If any error occurs, -1 is returned.
 */
int sign_server(s, service_name, dov2, once)
     int s;
     char *service_name;
     int dov2;
     int once;
{
     gss_cred_id_t server_creds;     
     gss_buffer_desc client_name, xmit_buf, msg_buf, context_token;
     gss_ctx_id_t context;
     OM_uint32 maj_stat, min_stat;
     int s2;
     time_t	now;
     
     if (server_acquire_creds(service_name, &server_creds) < 0)
	  return -1;
     
     while (1) {
	  if (s >= 0) {
	       /* Accept a TCP connection */
	      if ((s2 = accept(s, NULL, 0)) < 0) {
		    perror("accepting connection");
		    exit(1);
	       }
	  } else 
	       s2 = 0;

	  /* Establish a context with the client */
	  if (server_establish_context(s2, server_creds, &context,
				       &client_name) < 0)
	       break;
	  
	  time(&now);
	  fprintf(log, "Accepted connection: \"%s\" at %s", 
		  (char *) client_name.value, ctime(&now));
	  (void) gss_release_buffer(&min_stat, &client_name);

	  if (dov2) {
	      /*
	       * Attempt to save and then restore the context.
	       */
	      maj_stat = gss_export_sec_context(&min_stat,
						&context,
						&context_token);
	      if (maj_stat != GSS_S_COMPLETE) {
		  display_status("exporting context", maj_stat, min_stat);
		  break;
	      }
	      fprintf(log, "Exported context: %d bytes\n", context_token.length);
	      maj_stat = gss_import_sec_context(&min_stat,
						&context_token,
						&context);
	      if (maj_stat != GSS_S_COMPLETE) {
		  display_status("importing context", maj_stat, min_stat);
		  break;
	      }
	      (void) gss_release_buffer(&min_stat, &context_token);
	  }

	  /* Receive the sealed message token */
	  if (recv_token(s2, &xmit_buf) < 0)
	       break;

#ifdef	GSSAPI_V2
	  if (dov2)
	      maj_stat = gss_unwrap(&min_stat, context, &xmit_buf, &msg_buf,
				    (int *) NULL, (gss_qop_t *) NULL);
	  else
#endif	/* GSSAPI_V2 */
	  /* Unseal the message token */
	  maj_stat = gss_unseal(&min_stat, context, &xmit_buf,
				&msg_buf, NULL, NULL);
	  if (maj_stat != GSS_S_COMPLETE) {
	       display_status("unsealing message", maj_stat, min_stat);
	       break;
	  }

	  (void) gss_release_buffer(&min_stat, &xmit_buf);

	  fprintf(log, "Received message: \"%s\"\n", (char *) msg_buf.value);

	  /* Produce a signature block for the message */
#ifdef	GSSAPI_V2
	  if (dov2)
	      maj_stat = gss_get_mic(&min_stat, context, GSS_C_QOP_DEFAULT,
				     &msg_buf, &xmit_buf);
	  else
#endif	/* GSSAPI_V2 */
	  maj_stat = gss_sign(&min_stat, context, GSS_C_QOP_DEFAULT,
			      &msg_buf, &xmit_buf);
	  if (maj_stat != GSS_S_COMPLETE) {
	       display_status("signing message", maj_stat, min_stat);
	       break;
	  }

	  (void) gss_release_buffer(&min_stat, &msg_buf);

	  /* Send the signature block to the client */
	  if (send_token(s2, &xmit_buf) < 0)
	       break;

	  (void) gss_release_buffer(&min_stat, &xmit_buf);

	  /* Delete context */
	  maj_stat = gss_delete_sec_context(&min_stat, &context, &xmit_buf);
	  if (maj_stat != GSS_S_COMPLETE) {
	       display_status("deleting context", maj_stat, min_stat);
	       break;
	  }

	  (void) gss_release_buffer(&min_stat, &xmit_buf);

	  /* Close TCP connection */
	  close(s2);

	  fflush(log);

	  if (s < 0 || once)
	       break;
     }

     /*NOTREACHED*/
     (void) gss_release_cred(&min_stat, &server_creds);
     return -1;
}

/*
 * Function: server_acquire_creds
 *
 * Purpose: imports a service name and acquires credentials for it
 *
 * Arguments:
 *
 * 	service_name	(r) the ASCII service name
 * 	server_creds	(w) the GSS-API service credentials
 *
 * Returns: 0 on success, -1 on failure
 *
 * Effects:
 *
 * The service name is imported with gss_import_name, and service
 * credentials are acquired with gss_acquire_cred.  If either opertion
 * fails, an error message is displayed and -1 is returned; otherwise,
 * 0 is returned.
 */
int server_acquire_creds(service_name, server_creds)
     char *service_name;
     gss_cred_id_t *server_creds;
{
     gss_buffer_desc name_buf;
     gss_name_t server_name;
     OM_uint32 maj_stat, min_stat;

     name_buf.value = service_name;
     name_buf.length = strlen(name_buf.value) + 1;
     maj_stat = gss_import_name(&min_stat, &name_buf, 
				(gss_OID) gss_nt_service_name, &server_name);
     if (maj_stat != GSS_S_COMPLETE) {
	  display_status("importing name", maj_stat, min_stat);
	  return -1;
     }

     maj_stat = gss_acquire_cred(&min_stat, server_name, 0,
				 GSS_C_NULL_OID_SET, GSS_C_ACCEPT,
				 server_creds, NULL, NULL);
     if (maj_stat != GSS_S_COMPLETE) {
	  display_status("acquiring credentials", maj_stat, min_stat);
	  return -1;
     }

     (void) gss_release_name(&min_stat, &server_name);

     return 0;
}

/*
 * Function: server_establish_context
 *
 * Purpose: establishses a GSS-API context as a specified service with
 * an incoming client, and returns the context handle and associated
 * client name
 *
 * Arguments:
 *
 * 	s		(r) an established TCP connection to the client
 * 	service_creds	(r) server credentials, from gss_acquire_cred
 * 	context		(w) the established GSS-API context
 * 	client_name	(w) the client's ASCII name
 *
 * Returns: 0 on success, -1 on failure
 *
 * Effects:
 *
 * Any valid client request is accepted.  If a context is established,
 * its handle is returned in context and the client name is returned
 * in client_name and 0 is returned.  If unsuccessful, an error
 * message is displayed and -1 is returned.
 */
int server_establish_context(s, server_creds, context, client_name)
     int s;
     gss_cred_id_t server_creds;
     gss_ctx_id_t *context;
     gss_buffer_t client_name;
{
     gss_buffer_desc send_tok, recv_tok;
     gss_name_t client;
     gss_OID doid;
     OM_uint32 maj_stat, min_stat;
     OM_uint32 ret_flags;

     *context = GSS_C_NO_CONTEXT;
     
     do {
	  if (recv_token(s, &recv_tok) < 0)
	       return -1;

	  maj_stat =
	       gss_accept_sec_context(&min_stat,
				      context,
				      server_creds,
				      &recv_tok,
				      GSS_C_NO_CHANNEL_BINDINGS,
				      &client,
				      &doid,
				      &send_tok,
				      &ret_flags,
				      NULL, 	/* ignore time_rec */
				      NULL); 	/* ignore del_cred_handle */

	  if (maj_stat!=GSS_S_COMPLETE && maj_stat!=GSS_S_CONTINUE_NEEDED) {
	       display_status("accepting context", maj_stat, min_stat);
	       (void) gss_release_buffer(&min_stat, &recv_tok);
	       return -1;
	  }
	  (void) gss_release_buffer(&min_stat, &recv_tok);
	  

	  if (send_tok.length != 0) {
	       if (send_token(s, &send_tok) < 0) {
		    fprintf(log, "failure sending token\n");
		    return -1;
	       }

	       (void) gss_release_buffer(&min_stat, &send_tok);
	  }
     } while (maj_stat == GSS_S_CONTINUE_NEEDED);

     maj_stat = gss_display_name(&min_stat, client, client_name, &doid);
     if (maj_stat != GSS_S_COMPLETE) {
	  display_status("displaying name", maj_stat, min_stat);
	  return -1;
     }
     maj_stat = gss_release_name(&min_stat, &client);
     if (maj_stat != GSS_S_COMPLETE) {
	  display_status("releasing name", maj_stat, min_stat);
	  return -1;
     }
     return 0;
}

	  

