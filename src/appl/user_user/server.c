/*
 * $Source$
 * $Author$
 *
 * Copyright 1991 by the Massachusetts Institute of Technology.
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
 *
 * One end of the user-user client-server pair.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <fcntl.h>

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>
#include <krb5/los-proto.h>
#include <com_err.h>

extern krb5_flags krb5_kdc_default_options;

/* fd 0 is a tcp socket used to talk to the client */

int main(argc, argv)
int argc;
char *argv[];
{
  krb5_data pname_data, tkt_data;
  int l, sock = 0;
  int retval;
  struct sockaddr_in l_inaddr, f_inaddr;	/* local, foreign address */
  krb5_address laddr, faddr;
  krb5_creds creds;
  krb5_ccache cc;
  krb5_data msgtext, msg;
  krb5_int32 seqno;

#ifndef DEBUG
  freopen("/tmp/uu-server.log", "w", stderr);
#endif

  krb5_init_ets();

#ifdef DEBUG
    {
	int one = 1;
	int acc;
	struct servent *sp;
	int namelen = sizeof(f_inaddr);

	if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
	    com_err("uu-server", errno, "creating socket");
	    exit(3);
	}

	l_inaddr.sin_family = AF_INET;
	l_inaddr.sin_addr.s_addr = 0;
	if (!(sp = getservbyname("uu-sample", "tcp"))) {
	    com_err("uu-server", 0, "can't find uu-sample/tcp service");
	    exit(3);
	}
	(void) setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&one, sizeof (one));
	l_inaddr.sin_port = sp->s_port;
	if (bind(sock, (struct sockaddr *)&l_inaddr, sizeof(l_inaddr))) {
	    com_err("uu-server", errno, "binding socket");
	    exit(3);
	}
	if (listen(sock, 1) == -1) {
	    com_err("uu-server", errno, "listening");
	    exit(3);
	}
	if ((acc = accept(sock, (struct sockaddr *)&f_inaddr, &namelen)) == -1) {
	    com_err("uu-server", errno, "accepting");
	    exit(3);
	}
	dup2(acc, 0);
	close(sock);
	sock = 0;
    }
#endif
  if (retval = krb5_read_message((krb5_pointer) &sock, &pname_data)) {
      com_err ("uu-server", retval, "reading pname");
      return 2;
  }
  if (retval = krb5_read_message((krb5_pointer) &sock, &tkt_data)) {
      com_err ("uu-server", retval, "reading ticket data");
      return 2;
  }

  if (retval = krb5_cc_default(&cc))
    {
      com_err("uu-server", retval, "getting credentials cache");
      return 4;
    }

  memset ((char*)&creds, 0, sizeof(creds));
  if (retval = krb5_cc_get_principal(cc, &creds.client))
    {
      com_err("uu-client", retval, "getting principal name");
      return 6;
    }

  /* client sends it already null-terminated. */
  printf ("uu-server: client principal is \"%s\".\n", pname_data.data);

  if (retval = krb5_parse_name(pname_data.data, &creds.server))
    {
      com_err("uu-server", retval, "parsing client name");
      return 3;
    }
  creds.second_ticket = tkt_data;
  printf ("uu-server: client ticket is %d bytes.\n",
	  creds.second_ticket.length);

  if (retval = krb5_get_credentials(KRB5_GC_USER_USER, cc, &creds))
    {
      com_err("uu-server", retval, "getting user-user ticket");
      return 5;
    }

#ifndef DEBUG
  l = sizeof(f_inaddr);
  if (getpeername(0, (struct sockaddr *)&f_inaddr, &l) == -1)
    {
      com_err("uu-server", errno, "getting client address");
      return 6;
    }
#endif
  faddr.addrtype = ADDRTYPE_INET;
  faddr.length = sizeof (f_inaddr.sin_addr);
  faddr.contents = (krb5_octet *)&f_inaddr.sin_addr;

  l = sizeof(l_inaddr);
  if (getsockname(0, (struct sockaddr *)&l_inaddr, &l) == -1)
    {
      com_err("uu-server", errno, "getting local address");
      return 6;
    }

  laddr.addrtype = ADDRTYPE_INET;
  laddr.length = sizeof (l_inaddr.sin_addr);
  laddr.contents = (krb5_octet *)&l_inaddr.sin_addr;

  /* send a ticket/authenticator to the other side, so it can get the key
     we're using for the krb_safe below. */

  if (retval = krb5_generate_seq_number(&creds.keyblock, &seqno)) {
      com_err("uu-server", retval, "generating sequence number");
      return 8;
  }
#if 1
  if (retval = krb5_mk_req_extended(AP_OPTS_USE_SESSION_KEY,
			       0,	/* no application checksum here */
			       krb5_kdc_default_options,
			       seqno,
			       0,	/* no need for subkey */
			       cc,
			       &creds,
			       0,	/* don't need authenticator copy */
			       &msg)) {
      com_err("uu-server", retval, "making AP_REQ");
      return 8;
  }
  retval = krb5_write_message((krb5_pointer) &sock, &msg);
#else
  retval = krb5_sendauth((krb5_pointer)&sock, "???", 0, 0,
			 AP_OPTS_MUTUAL_REQUIRED | AP_OPTS_USE_SESSION_KEY,
			 0, /* no checksum*/
			 &creds, cc,
			 0, 0,	/* no sequence number or subsession key */
			 0, 0);
#endif
  if (retval)
      goto cl_short_wrt;

  free(msg.data);

  msgtext.length = 32;
  msgtext.data = "Hello, other end of connection.";

  if (retval = krb5_mk_safe(&msgtext, CKSUMTYPE_RSA_MD4_DES, &creds.keyblock,
			    &laddr, &faddr, seqno,
			    KRB5_SAFE_NOTIME|KRB5_SAFE_DOSEQUENCE, 0, &msg))
    {
      com_err("uu-server", retval, "encoding message to client");
      return 6;
    }

  retval = krb5_write_message((krb5_pointer) &sock, &msg);
  if (retval)
    {
    cl_short_wrt:
	com_err("uu-server", retval, "writing message to client");
      return 7;
    }

  return 0;
}
