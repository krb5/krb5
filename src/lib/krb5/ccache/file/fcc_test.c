/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_fcc_test_c [] =
"$Id$";
#endif	/* !lint & !SABER */

#include "fcc.h"

krb5_data client1 = {
#define DATA "client1-comp1"
     sizeof(DATA),
     DATA,
#undef DATA
};

krb5_data client2 = {
#define DATA "client1-comp2"
     sizeof(DATA),
     DATA,
#undef DATA
};

krb5_data server1 = {
#define DATA "server1-comp1"
     sizeof(DATA),
     DATA,
#undef DATA
};

krb5_data server2 = {
#define DATA "server1-comp2"
     sizeof(DATA),
     DATA,
#undef DATA
};

krb5_creds test_creds = {
     NULL,
     NULL,
     {
	  1,
	  1,
	  (unsigned char *) "1"
     },
     {
	  1111,
	  2222,
	  3333,
	  4444
     },
     1,
     5555,
     {
#define TICKET "This is ticket 1"
     sizeof(TICKET),
     TICKET,
#undef TICKET
     },
     {
#define TICKET "This is ticket 2"
     sizeof(TICKET),
     TICKET,
#undef TICKET
     },
};

void init_test_cred()
{
     test_creds.client = (krb5_principal) malloc(sizeof(krb5_data *)*3);
     test_creds.client[0] = &client1;
     test_creds.client[1] = &client2;
     test_creds.client[2] = NULL;

     test_creds.server = (krb5_principal) malloc(sizeof(krb5_data *)*3);
     test_creds.server[0] = &server1;
     test_creds.server[1] = &server2;
     test_creds.server[2] = NULL;
}

#define CHECK(kret,msg) \
     if (kret != KRB5_OK) {\
	  printf("%s returned %d\n", msg, kret);\
     };
						   
void fcc_test()
{
     krb5_ccache id;
     krb5_creds creds;
     krb5_error_code kret;
     krb5_cc_cursor cursor;

     init_test_cred();

     kret = krb5_fcc_resolve(&id, "/tmp/tkt_test");
     CHECK(kret, "resolve");
     kret = krb5_fcc_initialize(id, test_creds.client);
     CHECK(kret, "initialize");
     kret = krb5_fcc_store(id, &test_creds);
     CHECK(kret, "store");

     kret = krb5_fcc_start_seq_get(id, &cursor);
     CHECK(kret, "start_seq_get");
     kret = 0;
     while (kret != KRB5_CC_END) {
	  printf("Calling next_cred\n");
	  kret = krb5_fcc_next_cred(id, &cursor, &creds);
	  CHECK(kret, "next_cred");
     }
     kret = krb5_fcc_end_seq_get(id, &cursor);
     CHECK(kret, "end_seq_get");

     kret = krb5_fcc_destroy(id);
     CHECK(kret, "destroy");
     kret = krb5_fcc_close(id);
     CHECK(kret, "close");
}

