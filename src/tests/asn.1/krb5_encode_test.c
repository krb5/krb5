#include <stdio.h>
#include <krb5/krb5.h>
#include <krb5/asn1.h>
#include <com_err.h>
#include "utility.h"

#define initialize_error_tables()\
  initialize_isod_error_table();\
  initialize_krb5_error_table();

#include "krb5_encode_test_body.c"
