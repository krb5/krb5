/*
 * appl/user_user/client.c
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
 * Other end of user-user client/server pair.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>
#include <krb5/los-proto.h>
#include <com_err.h>

#include <krb5/widen.h>
krb5_error_code
tgt_keyproc(context, keyprocarg, principal, vno, key)
    krb5_context context;
    krb5_pointer keyprocarg;
    krb5_principal principal;
    krb5_kvno vno;
    krb5_keyblock ** key;
#include <krb5/narrow.h>
{
    krb5_creds *creds = (krb5_creds *)keyprocarg;
    
    return krb5_copy_keyblock(context, &creds->keyblock, key);
}

int main (argc, argv)
int argc;
char *argv[];
{
  int s;
  register int retval, i;
  char *hname;		/* full name of server */
  char **srealms;	/* realm(s) of server */
  char *princ;		/* principal in credentials cache */
  struct servent *serv;
  struct hostent *host;
  struct sockaddr_in serv_net_addr, cli_net_addr;
  krb5_address serv_addr, cli_addr;
  krb5_ccache cc;
  krb5_creds creds;
  krb5_data reply, msg, princ_data;
  krb5_tkt_authent *authdat;
  krb5_context context;
  unsigned short port;

  if (argc < 2 || argc > 4)
    {
      fputs ("usage: uu-client <hostname> [message [port]]\n", stderr);
      return 1;
    }

  krb5_init_context(&context);
  krb5_init_ets(context);

  if (argc == 4)
    {
      port = htons(atoi(argv[3]));
    }
  else if ((serv = getservbyname ("uu-sample", "tcp")) == NULL)
    {
      fputs ("uu-client: unknown service \"uu-sample/tcp\"\n", stderr);
      return 2;
    }
  else
    {
      port = serv->s_port;
    }

  if ((host = gethostbyname (argv[1])) == NULL)
    {
      extern int h_errno;

      if (h_errno == HOST_NOT_FOUND)
	fprintf (stderr, "uu-client: unknown host \"%s\".\n", argv[1]);
      else
	fprintf (stderr, "uu-client: can't get address of host \"%s\".\n", argv[1]);
      return 3;
    }

  if (host->h_addrtype != AF_INET)
    {
      fprintf (stderr, "uu-client: bad address type %d for \"%s\".\n",
	       host->h_addrtype, argv[1]);
      return 3;
    }

  hname = strdup (host->h_name);

#ifndef USE_STDOUT
  if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
      com_err ("uu-client", errno, "creating socket");
      return 4;
    } else {
      cli_net_addr.sin_family = AF_INET;
      cli_net_addr.sin_port = 0;
      cli_net_addr.sin_addr.s_addr = 0;
      if (bind (s, (struct sockaddr *)&cli_net_addr, sizeof (cli_net_addr)) < 0)
	{
	  com_err ("uu-client", errno, "binding socket");
	  return 4;
	}
    }

  serv_net_addr.sin_family = AF_INET;
  serv_net_addr.sin_port = port;

  i = 0;
  while (1)
    {
      if (host->h_addr_list[i] == 0)
	{
	  fprintf (stderr, "uu-client: unable to connect to \"%s\"\n", hname);
	  return 5;
	}
      memcpy ((char *)&serv_net_addr.sin_addr, host->h_addr_list[i++], host->h_length);
      if (connect(s, (struct sockaddr *)&serv_net_addr, sizeof (serv_net_addr)) == 0)
	break;
      com_err ("uu-client", errno, "connecting to \"%s\" (%s).",
	       hname, inet_ntoa(serv_net_addr.sin_addr));
    }
#else
  s = 1;
#endif

  if (retval = krb5_cc_default(context, &cc))
    {
      com_err("uu-client", retval, "getting credentials cache");
      return 6;
    }

  memset ((char*)&creds, 0, sizeof(creds));
  if (retval = krb5_cc_get_principal(context, cc, &creds.client))
    {
      com_err("uu-client", retval, "getting principal name");
      return 6;
    }

  if (retval = krb5_unparse_name(context, creds.client, &princ))
    com_err("uu-client", retval, "printing principal name");
  else
    fprintf(stderr, "uu-client: client principal is \"%s\".\n", princ);

  if (retval = krb5_get_host_realm(context, hname, &srealms))
    {
      com_err("uu-client", retval, "getting realms for \"%s\"", hname);
      return 7;
    }

  if (retval = krb5_build_principal_ext(context, &creds.server,
				krb5_princ_realm(context, creds.client)->length,
				krb5_princ_realm(context, creds.client)->data,
				6, "krbtgt",
				krb5_princ_realm(context, creds.client)->length,
				krb5_princ_realm(context, creds.client)->data,
					0))
    {
      com_err("uu-client", retval, "setting up tgt server name");
      return 7;
    }

  /* Get TGT from credentials cache */
  if (retval = krb5_get_credentials(context, KRB5_GC_CACHED, cc, &creds))
    {
      com_err("uu-client", retval, "getting TGT");
      return 6;
    }

  i = strlen(princ) + 1;

  fprintf(stderr, "uu-client: sending %d bytes\n", creds.ticket.length + i);
  princ_data.data = princ;
  princ_data.length = i;		/* include null terminator for
					   server's convenience */
  retval = krb5_write_message(context, (krb5_pointer) &s, &princ_data);
  if (retval)
    {
      com_err("uu-client", retval, "sending principal name to server");
      return 8;
    }
  free(princ);
  retval = krb5_write_message(context, (krb5_pointer) &s, &creds.ticket);
  if (retval)
    {
      com_err("uu-client", retval, "sending ticket to server");
      return 8;
    }

  retval = krb5_read_message(context, (krb5_pointer) &s, &reply);
  if (retval)
    {
	com_err("uu-client", retval, "reading reply from server");
      return 9;
    }
  serv_addr.addrtype = ADDRTYPE_INET;
  serv_addr.length = sizeof (serv_net_addr.sin_addr);
  serv_addr.contents = (krb5_octet *)&serv_net_addr.sin_addr;

  cli_addr.addrtype = ADDRTYPE_INET;
  cli_addr.length = sizeof(cli_net_addr.sin_addr);
  cli_addr.contents = (krb5_octet *)&cli_net_addr.sin_addr;

#if 1
  /* read the ap_req to get the session key */
  retval = krb5_rd_req(context, &reply,
		       0,		/* don't know server's name... */
		       &serv_addr,
		       0,		/* no fetchfrom */
		       tgt_keyproc,
		       (krb5_pointer)&creds, /* credentials as arg to
						keyproc */
		       0,		/* no rcache for the moment XXX */
		       &authdat);
  free(reply.data);
#else
  retval = krb5_recvauth(context, (krb5_pointer)&s, "???",
			 0, /* server */
			 &serv_addr, 0, tgt_keyproc, (krb5_pointer)&creds,
			 0, 0,
			 0, 0, 0, 0);
#endif
  if (retval) {
      com_err("uu-client", retval, "reading AP_REQ from server");
      return 9;
  }
  if (retval = krb5_unparse_name(context, authdat->ticket->enc_part2->client, &princ))
      com_err("uu-client", retval, "while unparsing client name");
  else {
      printf("server is named \"%s\"\n", princ);
      free(princ);
  }
  retval = krb5_read_message(context, (krb5_pointer) &s, &reply);
  if (retval)
    {
      com_err("uu-client", retval, "reading reply from server");
      return 9;
    }


  if (retval = krb5_rd_safe(context, &reply, authdat->ticket->enc_part2->session,
			    &serv_addr, &cli_addr,
			    authdat->authenticator->seq_number,
			    KRB5_SAFE_NOTIME|KRB5_SAFE_DOSEQUENCE, 0, &msg))
    {
      com_err("uu-client", retval, "decoding reply from server");
      return 10;
    }
  printf ("uu-client: server says \"%s\".\n", msg.data);
  return 0;
}

