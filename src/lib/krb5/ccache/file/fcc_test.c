#include <krb5/copyright.h>

#include "fcc.h"

krb5_data client[] = {
     {
#define DATA "client1-comp1"
	  sizeof(DATA),
	  DATA,
#undef DATA
     },
     {
#define DATA "client1-comp2"
	  sizeof(DATA),
	  DATA,
#undef DATA
     },
};

krb5_data server[] = {
     {
#define DATA "server1-comp1"
	  sizeof(DATA),
	  DATA,
#undef DATA
     },
     {
#define DATA "server1-comp2"
	  sizeof(DATA),
	  DATA,
#undef DATA
     },
};

krb5_creds test_creds = {
     NULL,
     NULL,
     {
	  1,
	  5,
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
     test_creds.client = &client;
     test_creds.server = &server;
}
