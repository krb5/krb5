/*

ARCFOUR cipher (based on a cipher posted on the Usenet in Spring-95).
This cipher is widely believed and has been tested to be equivalent
with the RC4 cipher from RSA Data Security, Inc.  (RC4 is a trademark
of RSA Data Security)

*/
#ifndef ARCFOUR_INT_H
#define ARCFOUR_INT_H

#include "arcfour.h"

#define CONFOUNDERLENGTH 8

typedef struct
{
   unsigned int x;
   unsigned int y;
   unsigned char state[256];
} ArcfourContext;

typedef struct {
  int initialized;
  ArcfourContext ctx;
} ArcFourCipherState;

krb5_keyusage krb5int_arcfour_translate_usage(krb5_keyusage usage);


#endif /* ARCFOUR_INT_H */
