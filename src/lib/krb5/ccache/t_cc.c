/*
 * lib/krb5/ccache/scc_test.c
 *
 * Copyright 2000 by the Massachusetts Institute of Technology.
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
 *
 */


#include "krb5.h"
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include "com_err.h"

#define KRB5_OK 0

krb5_creds test_creds;

int debug=0;

static void init_structs(void)
{
  static int add=0x12345;

  static krb5_address addr;

  static krb5_address *addrs[] = {
    &addr,
    0,
  };

  addr.magic = KV5M_ADDRESS;
  addr.addrtype = ADDRTYPE_INET;
  addr.length = 4;
  addr.contents = (krb5_octet *) &add;

  test_creds.magic = KV5M_CREDS;
  test_creds.client = NULL;
  test_creds.server = NULL;

  test_creds.keyblock.magic = KV5M_KEYBLOCK;
  test_creds.keyblock.contents = 0;
  test_creds.keyblock.enctype = 1;
  test_creds.keyblock.length = 1;
  test_creds.keyblock.contents = (unsigned char *) "1";
  test_creds.times.authtime = 1111;
  test_creds.times.starttime = 2222;
  test_creds.times.endtime = 3333;
  test_creds.times.renew_till = 4444;
  test_creds.is_skey = 1;
  test_creds.ticket_flags = 5555;
  test_creds.addresses = addrs;
  
#define SET_TICKET(ent, str) {ent.magic = KV5M_DATA; ent.length = sizeof(str); ent.data = str;}
  SET_TICKET(test_creds.ticket, "This is ticket 1");
  SET_TICKET(test_creds.second_ticket, "This is ticket 2");
  test_creds.authdata = NULL;
}

static void init_test_cred(krb5_context context)
{
#define REALM "REALM"
  krb5_build_principal(context, &test_creds.client, sizeof(REALM), REALM,
		       "client-comp1", "client-comp2", NULL);

  krb5_build_principal(context, &test_creds.server, sizeof(REALM), REALM,
		       "server-comp1", "server-comp2", NULL);
}

static void free_test_cred(krb5_context context)
{
  krb5_free_principal(context, test_creds.client);

  krb5_free_principal(context, test_creds.server);

}

#define CHECK(kret,msg) \
     if (kret != KRB5_OK) {\
	  com_err(msg, kret, ""); \
          fflush(stderr);\
          exit(1);\
     } else if(debug) printf("%s went ok\n", msg);

#define CHECK_STR(str,msg) \
     if (str == 0) {\
	  com_err(msg, kret, "");\
          exit(1);\
     } else if(debug) printf("%s went ok\n", msg);

#define CHECK_FAIL(experr, kret, msg) \
     if (experr != kret) { CHECK(kret, msg);}

static void cc_test(krb5_context context, const char *name, int flags)
{
     krb5_ccache id, id2;
     krb5_creds creds;
     krb5_error_code kret;
     krb5_cc_cursor cursor;
     const char *c_name;
     char newcache[300];

     init_test_cred(context);

     kret = krb5_cc_resolve(context, name, &id);
     CHECK(kret, "resolve");
     kret = krb5_cc_initialize(context, id, test_creds.client);
     CHECK(kret, "initialize");
     
     c_name = krb5_cc_get_name(context, id);
     CHECK_STR(c_name, "get_name");

     c_name = krb5_cc_get_type(context, id);
     CHECK_STR(c_name, "get_prefix");

     kret = krb5_cc_store_cred(context, id, &test_creds);
     CHECK(kret, "store");

     kret = krb5_cc_set_flags (context, id, flags);
     CHECK(kret, "set_flags");
     kret = krb5_cc_start_seq_get(context, id, &cursor);
     CHECK(kret, "start_seq_get");
     kret = 0;
     while (kret != KRB5_CC_END) {
	  if(debug) printf("Calling next_cred\n");
	  kret = krb5_cc_next_cred(context, id, &cursor, &creds);
	  if(kret == KRB5_CC_END) {
	    if(debug) printf("next_cred: ok at end\n");
	  }
	  else {
	    CHECK(kret, "next_cred");
	    krb5_free_cred_contents(context, &creds);
	  }

     }
     kret = krb5_cc_end_seq_get(context, id, &cursor);
     CHECK(kret, "end_seq_get");

     kret = krb5_cc_close(context, id);
     CHECK(kret, "close");


     /* ------------------------------------------------- */
     kret = krb5_cc_resolve(context, name, &id);
     CHECK(kret, "resolve2");

     {
       /* Copy the cache test*/
       sprintf(newcache, "%s.new", name);
       kret = krb5_cc_resolve(context, newcache, &id2);
       CHECK(kret, "resolve of new cache");
       
       /* This should fail as the new creds are not initialized */
       kret = krb5_cc_copy_creds(context, id, id2);
       CHECK_FAIL(KRB5_FCC_NOFILE, kret, "copy_creds");
       
       kret = krb5_cc_initialize(context, id2, test_creds.client);
       CHECK(kret, "initialize of id2");

       kret = krb5_cc_copy_creds(context, id, id2);
       CHECK(kret, "copy_creds");

       kret = krb5_cc_destroy(context, id2);
       CHECK(kret, "destroy new cache");
     }

     /* Destroy the first cache */
     kret = krb5_cc_destroy(context, id);
     CHECK(kret, "destroy");

#if 0
     /* ----------------------------------------------------- */
     /* Tests the generate new code */
     kret = krb5_cc_resolve(context, name, &id);
     CHECK(kret, "resolve");
     kret = krb5_cc_gen_new(context, &id);
     CHECK(kret, "gen_new");
     kret = krb5_cc_destroy(context, id);
     CHECK(kret, "destroy");
#endif

     free_test_cred(context);

}

static void do_test(krb5_context context, const char *prefix)
{
  char name[300];

  sprintf(name, "%s/tmp/cctest.%ld", prefix, (long) getpid());
  printf("Starting test on %s\n", name);
  cc_test (context, name, 0);
  cc_test (context, name, !0);
  printf("Test on %s passed\n", name);
}

static void test_misc(krb5_context context)
{
  /* Tests for certain error returns */
  krb5_error_code	kret;
  krb5_ccache id;
  extern krb5_cc_ops *krb5_cc_dfl_ops;
  krb5_cc_ops *ops_save;

  fprintf(stderr, "Testing miscellaneous error conditions\n");

  kret = krb5_cc_resolve(context, "unknown_method_ep:/tmp/name", &id);
  if (kret != KRB5_CC_UNKNOWN_TYPE) {
    CHECK(kret, "resolve unknown type");
  }

  /* Test for not specifiying a cache type with no defaults */
  ops_save = krb5_cc_dfl_ops;
  krb5_cc_dfl_ops = 0;

  kret = krb5_cc_resolve(context, "/tmp/e", &id);
  if (kret != KRB5_CC_BADNAME) {
    CHECK(kret, "resolve no builtin type");
  }

  krb5_cc_dfl_ops = ops_save;

}
extern const krb5_cc_ops krb5_mcc_ops;
extern const krb5_cc_ops krb5_fcc_ops;

int main (void)
{
    krb5_context context;
    krb5_error_code	kret;

    initialize_krb5_error_table ();

    if ((kret = krb5_init_context(&context))) {
	    printf("Couldn't initialize krb5 library: %s\n",
		   error_message(kret));
	    exit(1);
    }

    kret = krb5_cc_register(context, &krb5_mcc_ops,0);
    if(kret && kret != KRB5_CC_TYPE_EXISTS) {
      CHECK(kret, "register_mem");
    }

    kret = krb5_cc_register(context, &krb5_fcc_ops,0);
    if(kret && kret != KRB5_CC_TYPE_EXISTS) {
      CHECK(kret, "register_mem");
    }

    /* Registering a second time tests for error return */
    kret = krb5_cc_register(context, &krb5_fcc_ops,0);
    if(kret != KRB5_CC_TYPE_EXISTS) {
      CHECK(kret, "register_mem");
    }

    /* Registering with override should work */
    kret = krb5_cc_register(context, &krb5_fcc_ops,1);
    CHECK(kret, "register_mem override");

    init_structs();

    test_misc(context);
    do_test(context, "");
    do_test(context, "MEMORY:");
    do_test(context, "FILE:");

    krb5_free_context(context);
    return 0;
}
