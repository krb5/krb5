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

#include "k5-int.h"

#include <stdio.h>
#include <time.h>
#include <sys/types.h>

#ifndef _WIN32
#include <netinet/in.h>
#endif

#include <des.h>
#include <krb.h>
#include "com_err.h"

#define KEYSIZE 8
#define CRED_BUFSIZ 2048

#define krb5_print_addrs

void do_local (krb5_creds *, krb5_keyblock *),
     do_remote (krb5_context, krb5_creds *, char *, krb5_keyblock *);

static 
void print_key(msg, key)
     char *msg;
     des_cblock *key;
{
     printf("%s: ", msg);
     C_Block_print(key);
     printf("\n");
}

static
void print_time(msg, t)
     char *msg;
     int t;
{
     printf("%s: %d, %s", msg, t, ctime((time_t *) &t));
}

static
void krb5_print_times(msg, t)
     char *msg;
     krb5_ticket_times *t;
{
     printf("%s: Start: %d, %s", msg, t->starttime, 
	    ctime((time_t *) &t->starttime));
     printf("%s: End: %d, %s", msg, t->endtime, 
	    ctime((time_t *) &t->endtime));
     printf("%s: Auth: %d, %s", msg, t->authtime, 
	    ctime((time_t *) &t->authtime));
     printf("%s: Renew: %d, %s", msg, t->renew_till, 
	    ctime((time_t *) &t->renew_till));
}

static
void krb5_print_keyblock(msg, key)
     char *msg;
     krb5_keyblock *key;
{
     printf("%s: Keytype: %d\n", msg, key->enctype);
     printf("%s: Length: %d\n", msg, key->length);
     printf("%s: Key: ", msg);
     C_Block_print((des_cblock *) key->contents);
     printf("\n");
}

static
void krb5_print_ticket(context, ticket_data, key)
     krb5_context context;
     krb5_data *ticket_data;
     krb5_keyblock *key;
{
     char *p;
     krb5_ticket *tkt;
     int ret;

     if ((ret = decode_krb5_ticket(ticket_data, &tkt))) {
	  com_err("test", ret, "decoding ticket");
	  exit(1);
     }
     if ((ret = krb5_decrypt_tkt_part(context, key, tkt))) {
	  com_err("test", ret, "decrypting V5 ticket for print");
	  exit(1);
     }
     
     krb5_unparse_name(context, tkt->server, &p);
     printf("Ticket: Server: %s\n", p);
     free(p);
     printf("Ticket: kvno: %d\n", tkt->enc_part.kvno);
     printf("Ticket: Flags: 0x%08x\n", tkt->enc_part2->flags);
     krb5_print_keyblock("Ticket: Session Keyblock",
			 tkt->enc_part2->session);
     krb5_unparse_name(context, tkt->enc_part2->client, &p);
     printf("Ticket: Client: %s\n", p);
     free(p);
     krb5_print_times("Ticket: Times", &tkt->enc_part2->times);
     printf("Ticket: Address 0: %08lx\n",
	    *((unsigned long *) tkt->enc_part2->caddrs[0]->contents));
     
     krb5_free_ticket(context, tkt);
}

static
void krb5_print_creds(context, creds, secret_key)
     krb5_context context;
     krb5_creds *creds;
     krb5_keyblock *secret_key;
{
     char *p;
     
     krb5_unparse_name(context, creds->client, &p);
     printf("Client: %s\n", p);
     free(p);
     krb5_unparse_name(context, creds->server, &p);
     printf("Server: %s\n", p);
     free(p);
     krb5_print_keyblock("Session key", &creds->keyblock);
     krb5_print_times("Times", &creds->times);
     printf("is_skey: %s\n", creds->is_skey ? "True" : "False");
     printf("Flags: 0x%08x\n", creds->ticket_flags);
#if 0
     krb5_print_addrs(creds->addresses);
#endif
     krb5_print_ticket(context, &creds->ticket, secret_key);
     /* krb5_print_ticket(context, &creds->second_ticket, secret_key); */
}

static
void krb4_print_ticket(ticket, secret_key)
     KTEXT ticket;
     krb5_keyblock *secret_key;
{
     char pname[ANAME_SZ], pinst[INST_SZ], prealm[REALM_SZ];
     char sname[ANAME_SZ], sinst[INST_SZ];
     unsigned char flags;
     krb5_ui_4 addr;
     krb5_ui_4 issue_time;
     C_Block session_key;
     int life;
     Key_schedule keysched;
     
     int ret;
     
     if (des_key_sched(secret_key->contents, keysched)) {
	  fprintf(stderr, "Bug in DES key somewhere.\n");
	  exit(1);
     }
     
     ret = decomp_ticket(ticket, &flags, pname, pinst, prealm, &addr,
			 session_key, &life, &issue_time, sname,
			 sinst,  secret_key->contents, keysched);
     if (ret != KSUCCESS) {
	  fprintf(stderr, "krb4 decomp_ticket failed\n");
	  exit(1);
     }
     printf("Ticket: Client: %s.%s@%s\n", pname, pinst, prealm);
     printf("Ticket: Service: %s.%s\n", sname, sinst);
     printf("Ticket: Address: %08lx\n", (long) addr);
     print_key("Ticket: Session Key", (char *) session_key);
     printf("Ticket: Lifetime: %d\n", life);
     printf("Ticket: Issue Date: %ld, %s", (long) issue_time, 
	    ctime((time_t *) &issue_time));
}

static
void krb4_print_creds(creds, secret_key)
     CREDENTIALS *creds;
     krb5_keyblock *secret_key;
{
     printf("Client: %s.%s@%s\n", creds->pname, creds->pinst,
	    creds->realm);
     printf("Service: %s.%s@%s\n", creds->service, creds->instance,
	    creds->realm);
     print_key("Session key", (char *) creds->session);
     printf("Lifetime: %d\n", creds->lifetime);
     printf("Key Version: %d\n", creds->kvno);
     print_time("Issue Date", creds->issue_date);
     krb4_print_ticket(&creds->ticket_st, secret_key);
}

static
void usage()
{
     fprintf(stderr, "Usage: test [-remote server] client service\n");
     exit(1);
}

int main(argc, argv)
     int argc;
     char **argv;
{
     krb5_principal client, server;
     krb5_ccache cc;
     krb5_creds increds, *v5creds;
     krb5_keyblock key;
     char keybuf[KEYSIZE], buf[BUFSIZ];
     int i, ret, local;
     char *remote;
     krb5_context context;
     krb5_error_code retval;

#if 0
     krb524_debug = 1;
#endif

     retval = krb5_init_context(&context);
     if (retval) {
	     com_err(argv[0], retval, "while initializing krb5");
	     exit(1);
     }

     local = 0;
     remote = NULL;
     argc--; argv++;
     while (argc) {
	  if (strcmp(*argv, "-local") == 0)
	       local++;
#if 0
	  else if (strcmp(*argv, "-remote") == 0) {
	       argc--; argv++;
	       if (!argc)
		    usage();
	       remote = *argv;
	  }
#endif
	  else
	       break;
	  argc--; argv++;
     }
     if (argc != 2)
	  usage();

     if ((ret = krb5_parse_name(context, argv[0], &client))) {
	  com_err("test", ret, "parsing client name");
	  exit(1);
     }
     if ((ret = krb5_parse_name(context, argv[1], &server))) {
	  com_err("test", ret, "parsing server name");
	  exit(1);
     }
     if ((ret = krb5_cc_default(context, &cc))) {
	  com_err("test", ret, "opening default credentials cache");
	  exit(1);
     }
     
     memset((char *) &increds, 0, sizeof(increds));
     increds.client = client;
     increds.server = server;
     increds.times.endtime = 0;
     increds.keyblock.enctype = ENCTYPE_DES_CBC_MD5;
     if ((ret = krb5_get_credentials(context, 0, cc, &increds, &v5creds))) {
	  com_err("test", ret, "getting V5 credentials");
	  exit(1);
     }

     /* We need the service key in order to locally decrypt both */
     /* tickets for testing */
     printf("Service's key: ");
     fflush(stdout);
     fgets(buf, BUFSIZ, stdin);
     for (i = 0; i < 8; i++) {
	  unsigned char c;
	  c = buf[2*i];
	  if (c >= '0' && c <= '9')
	       c -= '0';
	  else if (c >= 'a' && c <= 'z')
	       c = c - 'a' + 0xa;
	  keybuf[i] = c << 4;
	  c = buf[2*i+1];
	  if (c >= '0' && c <= '9')
	       c -= '0';
	  else if (c >= 'a' && c <= 'z')
	       c = c - 'a' + 0xa;
	  keybuf[i] += c;
     }
     
     key.enctype = ENCTYPE_DES_CBC_MD5;
     key.length = KEYSIZE; /* presumably */
     key.contents = (krb5_octet *) keybuf;

     do_remote(context, v5creds, remote, &key);
     exit(0);
}

void do_remote(context, v5creds, server, key)
     krb5_context context;
     krb5_creds *v5creds;
     char *server;
     krb5_keyblock *key;
{
#if 0
     struct sockaddr_in saddr;
     struct hostent *hp;
#endif
     CREDENTIALS v4creds;
     int ret;

     printf("\nV5 credentials:\n");
     krb5_print_creds(context, v5creds, key);

#if 0
     if (strcmp(server, "kdc") != 0) {
	  hp = gethostbyname(server);
	  if (hp == NULL) {
	       fprintf(stderr, "test: host %s does not exist.\n", server);
	       exit(1);
	  }
	  memset((char *) &saddr, 0, sizeof(struct sockaddr_in));
	  saddr.sin_family = AF_INET;
	  memcpy((char *) &saddr.sin_addr.s_addr, hp->h_addr,
		 sizeof(struct in_addr));
	  
	  if ((ret = krb524_convert_creds_addr(context, v5creds, &v4creds, 
					      (struct sockaddr *) &saddr))) {
	       com_err("test", ret, "converting credentials on %s",
		       server);
	       exit(1);
	  }
     } else
#endif
     {
	  if ((ret = krb524_convert_creds_kdc(context, v5creds, &v4creds))) {
	       com_err("test", ret, "converting credentials via kdc");
	       exit(1);
	  }
     }
     
     printf("\nV4 credentials:\n");
     krb4_print_creds(&v4creds, key);
}
