#include <stdio.h>
#include <rpc/types.h>
#include <krb5.h>

#define stringify(a) #a

#define test_size(a,b) if (sizeof(a) != sizeof(b)) { \
  fprintf(stderr, "sizeof(%s) != sizeof(%s)\n", stringify(a), stringify(b)); \
  exit(1); \
}

main()
{
  test_size(unsigned long, krb5_ui_4);
  test_size(long, krb5_timestamp);
  test_size(long, krb5_deltat);
  test_size(long, krb5_flags);

  exit(0);
}

