/*
Copyright 1990, Daniel J. Bernstein. All rights reserved.

Please address any questions or comments to the author at brnstnd@acf10.nyu.edu.
*/

#include <string.h>
#include <malloc.h>
extern char *getenv(char *); /* ain't there an include file for this? */
#ifdef SEMAPHORE
#include <semaphore.h>
#endif
#include "rc_base.h"
#include "rc_err.h"

static struct krb5_rc_typelist
 {
  struct krb5_rc_type *ops;
  struct krb5_rc_typelist *next;
 }
*typehead = (struct krb5_rc_typelist *) 0;

#ifdef SEMAPHORE
semaphore ex_typelist = 1;
#endif

krb5_error_code krb5_rc_register_type(struct krb5_rc_type *ops)
{
 struct krb5_rc_typelist *t;
#ifdef SEMAPHORE
 down(&ex_typelist);
#endif
 for (t = typehead;t && strcmp(t->ops->type,ops->type);t = t->next)
   ;
#ifdef SEMAPHORE
 up(&ex_typelist);
#endif
 if (t)
   return KRB5_RC_EXIST;
 if (!(t = (struct krb5_rc_typelist *) malloc(sizeof(struct krb5_rc_typelist))))
   return KRB5_RC_MALLOC;
#ifdef SEMAPHORE
 down(&ex_typelist);
#endif
 t->next = typehead;
 t->ops = ops;
 typehead = t;
#ifdef SEMAPHORE
 up(&ex_typelist);
#endif
 return 0;
}

krb5_error_code krb5_rc_resolve_type(krb5_RC *id,char *type)
{
 struct krb5_rc_typelist *t;
#ifdef SEMAPHORE
 down(&ex_typelist);
#endif
 for (t = typehead;t && strcmp(t->ops->type,type);t = t->next)
   ;
#ifdef SEMAPHORE
 up(&ex_typelist);
#endif
 if (!t)
   return KRB5_RC_NOTFOUND;
 /* allocate *id? nah */
 (*id)->ops = t->ops;
 return 0;
}

char *krb5_rc_get_type(krb5_RC id)
{
 return id->ops->type;
}

char *krb5_rc_default_type(void)
{
 char *s;
 if (s = getenv("KRB5RCACHETYPE"))
   return s;
 else
   return "dfl";
}

char *krb5_rc_default_name(void)
{
 char *s;
 if (s = getenv("KRB5RCACHENAME"))
   return s;
 else
   return (char *) 0;
}
