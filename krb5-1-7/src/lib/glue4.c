#include "krb5.h"

krb5_data string_list[3] = {
{11, "FOO.MIT.EDU"},
{6, "jtkohl"},
};

krb5_data *princ[] = {&string_list[0], &string_list[1], 0};

krb5_data string_list2[3] = {
{11, "FOO.MIT.EDU"},
{4, "rcmd"},
{13, "lycus.mit.edu"},
};

krb5_data *princ2[] = {&string_list2[0], &string_list2[1], &string_list2[2], 0};
				   
krb5_last_req_entry lrentries[] = { {32000, 1}, {0, 3}, {10, 2} };
krb5_last_req_entry *lrfoo1[] = {&lrentries[0], &lrentries[1], &lrentries[2], 0};
