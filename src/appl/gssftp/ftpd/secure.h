#include <stdio.h>

#define CRED_DECL	extern AUTH_DAT kdata;
#define SESSION		kdata.session
#define myaddr		data_source
#define hisaddr		data_dest

int secure_flush PROTOTYPE((int));
int secure_putc PROTOTYPE((int, FILE *));
int secure_getc PROTOTYPE((FILE *));
int secure_write PROTOTYPE((int, unsigned char *, unsigned int));
int secure_read PROTOTYPE((int, char *, unsigned int));
void secure_gss_error PROTOTYPE((OM_uint32 maj_stat, OM_uint32 min_stat, char *s));

#if defined(STDARG) || (defined(__STDC__) && ! defined(VARARGS)) || defined(HAVE_STDARG_H)
void secure_error(char *, ...);
#else
void secure_error();
#endif
