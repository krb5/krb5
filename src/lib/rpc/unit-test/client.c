/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved.
 *
 * $Id$
 * $Source$
 * 
 * $Log$
 * Revision 1.13  1996/07/22 20:41:40  marc
 * this commit includes all the changes on the OV_9510_INTEGRATION and
 * OV_MERGE branches.  This includes, but is not limited to, the new openvision
 * admin system, and major changes to gssapi to add functionality, and bring
 * the implementation in line with rfc1964.  before committing, the
 * code was built and tested for netbsd and solaris.
 *
 * Revision 1.12.4.1  1996/07/18 04:20:03  marc
 * merged in changes from OV_9510_BP to OV_9510_FINAL1
 *
 * Revision 1.12.2.1  1996/06/20  23:41:56  marc
 * File added to the repository on a branch
 *
 * Revision 1.12  1996/05/12  06:58:10  marc
 * type renamings for compatibility with beta6
 *
 * Revision 1.11  1996/02/12  15:58:42  grier
 * [secure/3570]
 * long conversion
 *
 * Revision 1.10  1995/12/07  17:37:03  jik
 * Use "rpc_test" instead of "rpc-test", to avoid problems with rpcgen on
 * some systems.  See PR 3553.
 *
 * Revision 1.9  1994/09/21 18:38:56  bjaspan
 * [secure-rpc/2536: unit test client.c: memory initialization and out-of-bounds reference bugs]
 * [secure-releng/2537: audit secure-rpc/2536: minor memory problems in unit-test client]
 *
 * Sandbox:
 *
 *  1. Don't allow the count specifie on the command line to be bigger
 *     than the size of the buffer use for testing.
 *  2. When initializing the buffer for the lengths test, initialize it to
 *     count bytes.
 *
 * Revision 1.9  1994/09/19  01:28:04  root
 * 1. Don't allow the count specifie on the command line to be bigger
 *    than the size of the buffer use for testing.
 * 2. When initializing the buffer for the lengths test, initialize it to
 *    count bytes.
 *
 * Revision 1.8  1994/04/06  22:13:01  jik
 * Change -auth_once to -o, add -a, -m and -s arguments to set
 * auth_debug_gssapi, svc_debug_gssapi and misc_debug_gssapi variables.
 *
 * Revision 1.7  1994/04/05  20:50:09  bjaspan
 * fix typo that causes coredump when server blocks/fails
 *
 * Revision 1.6  1993/12/08  21:44:45  bjaspan
 * test fix for secure-rpc/586, improve arg handlng
 *
 * Revision 1.5  1993/12/06  21:23:30  bjaspan
 * accept count arg for RPC_TEST_LENGTHS
 *
 * Revision 1.4  1993/12/01  23:41:45  bjaspan
 * don't free echo_resp if call fails
 *
 * Revision 1.3  1993/11/15  19:53:09  bjaspan
 * test auto-syncrhonization
 *
 * Revision 1.2  1993/11/12  02:33:43  bjaspan
 * use clnt_pcreateerror for auth failures
 *
 * Revision 1.1  1993/11/03  23:53:58  bjaspan
 * Initial revision
 *
 */

#if !defined(lint) && !defined(__CODECENTER__)
static char *rcsid = "$Header$";
#endif

#include <stdio.h>
#include <rpc/rpc.h>
#include <gssapi/gssapi.h>
#include <rpc/rpc.h>
#include <rpc/auth_gssapi.h>
#include "rpc_test.h"

#define BIG_BUF 4096
/* copied from auth_gssapi.c for hackery */
struct auth_gssapi_data {
     bool_t established;
     CLIENT *clnt;
     gss_ctx_id_t context;
     gss_buffer_desc client_handle;
     OM_uint32 seq_num;
     int def_cred;

     /* pre-serialized ah_cred */
     u_char cred_buf[MAX_AUTH_BYTES];
     rpc_int32 cred_len;
};
#define AUTH_PRIVATE(auth) ((struct auth_gssapi_data *)auth->ah_private)

extern int auth_debug_gssapi;
char *whoami;

main(argc, argv)
   int argc;
   char **argv;
{
     char        *host, *target, *echo_arg, **echo_resp, buf[BIG_BUF];
     CLIENT      *clnt;
     AUTH	 *tmp_auth;
     struct rpc_err e;
     int i, count, auth_once;
     extern int optind;
     extern char *optarg;
     extern int svc_debug_gssapi, misc_debug_gssapi, auth_debug_gssapi;
     int c;

     whoami = argv[0];
     count = 1026;
     auth_once = 0;
     
     while ((c = getopt(argc, argv, "a:m:os:")) != -1) {
	  switch (c) {
	  case 'a':
	       auth_debug_gssapi = atoi(optarg);
	       break;
	  case 'm':
	       misc_debug_gssapi = atoi(optarg);
	       break;
	  case 'o':
	       auth_once++;
	       break;
	  case 's':
	       svc_debug_gssapi = atoi(optarg);
	       break;
	  case '?':
	       usage();
	       break;
	  }
     }

     argv += optind;
     argc -= optind;

     switch (argc) {
     case 3:
	  count = atoi(argv[2]);
	  if (count > BIG_BUF) {
	    fprintf(stderr, "Test count cannot exceed %d.\n", BIG_BUF);
	    usage();
	  }
     case 2:
	  host = argv[0];
	  target = argv[1];
	  break;
     default:
	  usage();
     }
     
     /* client handle to rstat */
     clnt = clnt_create(host, RPC_TEST_PROG, RPC_TEST_VERS_1, "tcp");
     if (clnt == NULL) {
	  clnt_pcreateerror(whoami);
	  exit(1);
     }
     
     clnt->cl_auth = auth_gssapi_create_default(clnt, target);
     if (clnt->cl_auth == NULL) {
	  clnt_pcreateerror(whoami);
	  exit(2);
     }
     
     /*
      * Call the echo service multiple times.
      */
     echo_arg = buf;
     for (i = 0; i < 3; i++) {
	  sprintf(buf, "testing %d\n", i);

	  echo_resp = rpc_test_echo_1(&echo_arg, clnt);
	  if (echo_resp == NULL) {
	       fprintf(stderr, "RPC_TEST_ECHO call %d%s", i,
		       clnt_sperror(clnt, ""));
	  }
	  if (strncmp(*echo_resp, "Echo: ", 6) &&
	      strcmp(echo_arg, (*echo_resp) + 6) != 0)
	       fprintf(stderr, "RPC_TEST_ECHO call %d response wrong: "
		       "arg = %s, resp = %s\n", echo_arg, *echo_resp);
	  xdr_free(xdr_wrapstring, echo_resp);
     }

     /*
      * Make a call with an invalid verifier and check for error;
      * server should log error message.  It is important to
      *increment* seq_num here, since a decrement would be fixed (see
      * below).  Note that seq_num will be incremented (by
      * authg_gssapi_refresh) twice, so we need to decrement by three
      * to reset.
      */
     AUTH_PRIVATE(clnt->cl_auth)->seq_num++;

     echo_arg = "testing with bad verf";

     echo_resp = rpc_test_echo_1(&echo_arg, clnt);
     if (echo_resp == NULL) {
	  CLNT_GETERR(clnt, &e);
	  if (e.re_status != RPC_AUTHERROR || e.re_why != AUTH_REJECTEDVERF)
	       clnt_perror(clnt, whoami);
     } else {
	  fprintf(stderr, "bad seq didn't cause failure\n");
     }

     AUTH_PRIVATE(clnt->cl_auth)->seq_num -= 3;

     /*
      * Make sure we're resyncronized.
      */
     echo_arg = "testing for reset";
     echo_resp = rpc_test_echo_1(&echo_arg, clnt);
     if (echo_resp == NULL)
	  clnt_perror(clnt, "Sequence number improperly reset");
     
     /*
      * Now simulate a lost server response, and see if
      * auth_gssapi_refresh recovers.
      */
     AUTH_PRIVATE(clnt->cl_auth)->seq_num--;
     echo_arg = "forcing auto-resynchronization";
     echo_resp = rpc_test_echo_1(&echo_arg, clnt);
     if (echo_resp == NULL)
	  clnt_perror(clnt, "Auto-resynchronization failed");
     
     /*
      * Now make sure auto-resyncrhonization actually worked
      */
     echo_arg = "testing for resynchronization";
     echo_resp = rpc_test_echo_1(&echo_arg, clnt);
     if (echo_resp == NULL)
	  clnt_perror(clnt, "Auto-resynchronization did not work");

     /*
      * Test fix for secure-rpc/586, part 1: btree keys must be
      * unique.  Create another context from the same credentials; it
      * should have the same expiration time and will cause the server
      * to abort if the clients are not differentiated.
      * 
      * Test fix for secure-rpc/586, part 2: btree keys cannot be
      * mutated in place.  To test this: a second client, *with a
      * later expiration time*, must be run.  The second client should
      * destroy itself *after* the first one; if the key-mutating bug
      * is not fixed, the second client_data will be in the btree
      * before the first, but its key will be larger; thus, when the
      * first client calls AUTH_DESTROY, the server won't find it in
      * the btree and call abort.
      *
      * For unknown reasons, running just a second client didn't
      * tickle the bug; the btree code seemed to guess which node to
      * look at first.  Running a total of three clients does ticket
      * the bug.  Thus, the full test sequence looks like this:
      *
      * 	kinit -l 20m user && client server test@ddn 200
      * 	sleep 1
      * 	kini -l 30m user && client server test@ddn 300
      * 	sleep 1
      * 	kinit -l 40m user && client server test@ddn 400
      */
     if (! auth_once) {
	  tmp_auth = clnt->cl_auth;
	  clnt->cl_auth = auth_gssapi_create_default(clnt, target);
	  if (clnt->cl_auth == NULL) {
	       clnt_pcreateerror(whoami);
	       exit(2);
	  }
	  AUTH_DESTROY(clnt->cl_auth);
	  clnt->cl_auth = tmp_auth;
     }
     
     /*
      * Try RPC calls with argument/result lengths [0, 1025].  Do
      * this last, since it takes a while..
      */
     echo_arg = buf;
     memset(buf, 0, count);
     for (i = 0; i < count; i++) {
	  echo_resp = rpc_test_echo_1(&echo_arg, clnt);
	  if (echo_resp == NULL) {
	       fprintf(stderr, "RPC_TEST_LENGTHS call %d%s", i,
		       clnt_sperror(clnt, ""));
	       break;
	  } else {
	       if (strncmp(*echo_resp, "Echo: ", 6) &&
		   strcmp(echo_arg, (*echo_resp) + 6) != 0)
		    fprintf(stderr,
			    "RPC_TEST_LENGTHS call %d response wrong\n");
	       xdr_free(xdr_wrapstring, echo_resp);
	  }
	  
	  /* cycle from 1 to 255 */
	  buf[i] = (i % 255) + 1;

	  if (i % 100 == 0) {
	       fputc('.', stdout);
	       fflush(stdout);
	  }
     }
     fputc('\n', stdout);

     AUTH_DESTROY(clnt->cl_auth);
     CLNT_DESTROY(clnt);
     exit(0);
}

usage()
{
     fprintf(stderr, "usage: %s [-a] [-s num] [-m num] host service [count]\n",
	     whoami);
     exit(1);
}
