/*
 * rd_svc_key.c
 *
 * Copyright 1985, 1986, 1987, 1988 by the Massachusetts Institute
 * of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 */

#include "mit-copyright.h"
#include "krb.h"
#include <stdio.h>
#include <string.h>

extern char *krb__get_srvtabname();

/*
 * The private keys for servers on a given host are stored in a
 * "srvtab" file (typically "/etc/srvtab").  This routine extracts
 * a given server's key from the file.
 *
 * read_service_key() takes the server's name ("service"), "instance",
 * and "realm" and a key version number "kvno", and looks in the given
 * "file" for the corresponding entry, and if found, returns the entry's
 * key field in "key".
 * 
 * If "instance" contains the string "*", then it will match
 * any instance, and the chosen instance will be copied to that
 * string.  For this reason it is important that the there is enough
 * space beyond the "*" to receive the entry.
 *
 * If "kvno" is 0, it is treated as a wild card and the first
 * matching entry regardless of the "vno" field is returned.
 *
 * This routine returns KSUCCESS on success, otherwise KFAILURE.
 *
 * The format of each "srvtab" entry is as follows:
 *
 * Size			Variable		Field in file
 * ----			--------		-------------
 * string		serv			server name
 * string		inst			server instance
 * string		realm			server realm
 * 1 byte		vno			server key version #
 * 8 bytes		key			server's key
 * ...			...			...
 */

#ifdef __i960__
/* special hack to use a global srvtab variable... */
#define open vxworks_srvtab_open
#define close vxworks_srvtab_close
#define getst vxworks_srvtab_getst
#define read vxworks_srvtab_read

extern char *vxworks_srvtab_base;
char *vxworks_srvtab_ptr;
int vxworks_srvtab_getchar(s)
     char *s;
{
  int tmp1;
  if(vxworks_srvtab_ptr >= (vxworks_srvtab_base + strlen(vxworks_srvtab_base)))
    return 0;

  sscanf(vxworks_srvtab_ptr, "%2x", &tmp1);

  *s = tmp1;
  vxworks_srvtab_ptr+=2;
  return 1;
}

int vxworks_srvtab_getst(fd,s,n)
    int fd;
    register char *s;
    int n;
{
    register count = n;
    while (vxworks_srvtab_getchar(s) && --count)
        if (*s++ == '\0')
            return (n - count);
    *s = '\0';
    return (n - count);
}

int vxworks_srvtab_open(s, n, m)
     char *s;
     int n, m;
{
  vxworks_srvtab_ptr = vxworks_srvtab_base;
  return 1;
}

int vxworks_srvtab_close(fd)
     int fd;
{
  vxworks_srvtab_ptr = 0;
  return 0;
}

int vxworks_srvtab_read(fd, s, n)
     int fd;
     char *s;
     int n;
{
  int count = n;
  /* we want to get exactly n chars. */
  while(vxworks_srvtab_getchar(s) && --count)
    s++;
  return (n-count);
}
#endif

int read_service_key(service,instance,realm,kvno,file,key)
    char *service;              /* Service Name */
    char *instance;             /* Instance name or "*" */
    char *realm;                /* Realm */
    int kvno;                   /* Key version number */
    char *file;                 /* Filename */
    char *key;                  /* Pointer to key to be filled in */
{
    return get_service_key(service,instance,realm,&kvno,file,key);
}

/* kvno is passed by reference, so that if it is zero, and we find a match,
   the match gets written back into *kvno so the caller can find it.
 */
int get_service_key(service,instance,realm,kvno,file,key)
    char *service;              /* Service Name */
    char *instance;             /* Instance name or "*" */
    char *realm;                /* Realm */
    int  *kvno;                 /* Key version number */
    char *file;                 /* Filename */
    char *key;                  /* Pointer to key to be filled in */
{
    char serv[SNAME_SZ];
    char inst[INST_SZ];
    char rlm[REALM_SZ];
    unsigned char vno;          /* Key version number */
    int wcard;
    char krb_realm[REALM_SZ];

    int stab, open();

    if (!file)
	file = KEYFILE;

    if ((stab = open(file, 0, 0)) < 0)
        return(KFAILURE);

    wcard = (instance[0] == '*') && (instance[1] == '\0');
    /* get current realm if not passed in */
    if (!realm) {
	int rem;

	rem = krb_get_lrealm(krb_realm,1);
	if (rem != KSUCCESS)
	    return(rem);
	realm = krb_realm;
    }

    while(getst(stab,serv,SNAME_SZ) > 0) { /* Read sname */
        (void) getst(stab,inst,INST_SZ); /* Instance */
        (void) getst(stab,rlm,REALM_SZ); /* Realm */
        /* Vers number */
        if (read(stab,(char *)&vno,1) != 1) {
	    close(stab);
            return(KFAILURE);
	}
        /* Key */
        if (read(stab,key,8) != 8) {
	    close(stab);
            return(KFAILURE);
	}
        /* Is this the right service */
        if (strcmp(serv,service))
            continue;
        /* How about instance */
        if (!wcard && strcmp(inst,instance))
            continue;
        if (wcard)
            (void) strncpy(instance,inst,INST_SZ);
        /* Is this the right realm */
#if defined(ATHENA_COMPAT) || defined(ATHENA_OLD_SRVTAB)
	/* XXX For backward compatibility:  if keyfile says "Athena"
	   and caller wants "ATHENA.MIT.EDU", call it a match */
        if (strcmp(rlm,realm) &&
	    (strcmp(rlm,"Athena") ||
	     strcmp(realm,"ATHENA.MIT.EDU")))
	    continue;
#else /* ! ATHENA_COMPAT */
        if (strcmp(rlm,realm)) 
	    continue;
#endif /* ATHENA_COMPAT */

        /* How about the key version number */
        if (*kvno && *kvno != (int) vno)
            continue;

        (void) close(stab);
	*kvno = vno;
        return(KSUCCESS);
    }

    /* Can't find the requested service */
    (void) close(stab);
    return(KFAILURE);
}
