#include <krb5/krb5.h>

krb5_data string_list[3] = {
{14, "ATHENA.MIT.EDU"},
{6, "jtkohl"},
{4, "root"},
};

krb5_data *princ[] = {&string_list[0], &string_list[1], &string_list[2], 0};

krb5_data string_list2[3] = {
{14, "ATHENA.MIT.EDU"},
{6, "krbtgt"},
{14, "ATHENA.MIT.EDU"},
};

krb5_data *princ2[] = {&string_list2[0], &string_list2[1], &string_list2[2], 0};
				   
krb5_last_req_entry lrentries[] = { {32000, 1}, {0, 3}, {10, 2} };
krb5_last_req_entry *lrfoo1[] = {&lrentries[0], &lrentries[1], &lrentries[2], 0};

krb5_authdata adarr1[] = { {3, 7, "authdat"}, {2,4,"foob"}, {257,9,"jtkohlxxx"}};
krb5_authdata *authdats[] = {&adarr1[0],&adarr1[1],&adarr1[2],0};

krb5_pa_data authdarr1[] = { {3, 7, "authdat"}, {2,4,"foob"}, {257,9,"jtkohlxxx"}};
krb5_pa_data *padats[] = {&authdarr1[0],&authdarr1[1],&authdarr1[2],0};

krb5_address adrarr1[] = { {ADDRTYPE_INET,4,"abcd"},
			   {ADDRTYPE_ISO,10,"6176432831"},
			   {ADDRTYPE_INET,4,"efgh"} };
krb5_address *addrs[] = {&adrarr1[0],&adrarr1[1],&adrarr1[2],0};
