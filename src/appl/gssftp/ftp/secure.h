#include <stdio.h>

#define CRED_DECL	extern CREDENTIALS cred;
#define SESSION		&cred.session
#define myaddr		data_addr
#define hisaddr		hisdataaddr

#ifndef PROTOTYPE
#define PROTOTYPE(x) x
#endif

int secure_flush PROTOTYPE((int));
int secure_putc PROTOTYPE((int, FILE *));
int secure_getc PROTOTYPE((FILE *));
int secure_write PROTOTYPE((int, unsigned char *, unsigned int));
int secure_read PROTOTYPE((int, char *, unsigned int));
void secure_gss_error PROTOTYPE((OM_uint32 maj_stat, OM_uint32 min_stat, char *s));

void secure_error(char *, ...);
