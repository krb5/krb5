/*
 * $Source$
 * $Author$
 *
 * This part of the Kerberos V5 software is derived from public-domain code
 * contributed by Daniel J. Bernstein, <brnstnd@acf10.nyu.edu>.
 *
 * XXX correct notice?
 * This portion of the software may be freely distributed; this permission
 * shall not be construed to apply to any other portion of the software.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_rc_base_c[] =
"$Id$";
#endif	/* !lint & !SABER */

/*
 * Base "glue" functions for the replay cache.
 */

#ifdef SEMAPHORE
#include <semaphore.h>
#endif
#include "rc_base.h"

#define FREE(x) ((void) free((char *) (x)))

struct krb5_rc_typelist
 {
  krb5_rc_ops *ops;
  struct krb5_rc_typelist *next;
 };
static struct krb5_rc_typelist krb5_rc_typelist_dfl = { &krb5_rc_dfl_ops, 0 };
static struct krb5_rc_typelist *typehead = &krb5_rc_typelist_dfl;

#ifdef SEMAPHORE
semaphore ex_typelist = 1;
#endif

krb5_error_code krb5_rc_register_type(ops)
krb5_rc_ops *ops;
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
   return KRB5_RC_TYPE_EXISTS;
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

krb5_error_code krb5_rc_resolve_type(id, type)
krb5_rcache *id;
char *type;
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
   return KRB5_RC_TYPE_NOTFOUND;
 /* allocate *id? nah */
 (*id)->ops = t->ops;
 return 0;
}

char *krb5_rc_get_type(id)
krb5_rcache id;
{
 return id->ops->type;
}

#ifdef __STDC__
char *krb5_rc_default_type(void)
#else
char *krb5_rc_default_type()
#endif
{
 char *s;
 if (s = getenv("KRB5RCACHETYPE"))
   return s;
 else
   return "dfl";
}

#ifdef __STDC__
char *krb5_rc_default_name(void)
#else
char *krb5_rc_default_name()
#endif
{
 char *s;
 if (s = getenv("KRB5RCACHENAME"))
   return s;
 else
   return (char *) 0;
}

krb5_error_code
krb5_rc_default(id)
krb5_rcache *id;
{
    krb5_error_code retval;

    if (!(*id = (krb5_rcache )malloc(sizeof(**id))))
	return KRB5_RC_MALLOC;

    if (retval = krb5_rc_resolve_type(id, krb5_rc_default_type())) {
	FREE(*id);
	return retval;
    }
    if (retval = krb5_rc_resolve(*id, krb5_rc_default_name()))
	FREE(*id);
    return retval;
}


krb5_error_code krb5_rc_resolve_full(id, string_name)
krb5_rcache *id;
char *string_name;
{
    char *type;
    char *residual;
    krb5_error_code retval;

    if (!(residual = strchr(string_name,':')))
	return KRB5_RC_PARSE;
 
    if (!(type = malloc(residual - string_name + 1)))
	return KRB5_RC_MALLOC;
    (void) strncpy(type,string_name,residual - string_name);
    type[residual - string_name] = '\0';

    if (!(*id = (krb5_rcache) malloc(sizeof(**id)))) {
	FREE(type);
	return KRB5_RC_MALLOC;
    }

    if (retval = krb5_rc_resolve_type(id,type)) {
	FREE(type);
	FREE(*id);
	return retval;
    }
    FREE(type);
    if (retval = krb5_rc_resolve(*id,residual + 1))
	FREE(*id);
    return retval;
}

