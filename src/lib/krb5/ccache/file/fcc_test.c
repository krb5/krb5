#include <krb5/copyright.h>

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
	  "1"
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
