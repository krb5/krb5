#include <stdio.h>

#define CRED_DECL	extern CREDENTIALS cred;
#define SESSION		&cred.session
#define myaddr		data_addr
#define hisaddr		hisdataaddr

int secure_flush (int);
int secure_putc (int, FILE *);
int secure_getc (FILE *);
int secure_write (int, unsigned char *, unsigned int);
int secure_read (int, char *, unsigned int);
void secure_gss_error (OM_uint32 maj_stat, OM_uint32 min_stat, char *s);

void secure_error(char *, ...);
