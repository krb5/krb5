/*
 * in_tkt.c
 *
 * Copyright 1985, 1986, 1987, 1988 by the Massachusetts Institute
 * of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 */

#include "mit-copyright.h"
#include <stdio.h>
#include <string.h>
#include "krb.h"
#include <fcntl.h>
#include <sys/stat.h>
#ifdef TKT_SHMEM
#include <sys/param.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

extern int krb_debug;

/*
 * in_tkt() is used to initialize the ticket store.  It creates the
 * file to contain the tickets and writes the given user's name "pname"
 * and instance "pinst" in the file.  in_tkt() returns KSUCCESS on
 * success, or KFAILURE if something goes wrong.
 */

#ifdef HAVE_SETEUID
#define do_seteuid(e) seteuid((e))
#else
#ifdef HAVE_SETRESUID
#define do_seteuid(e) setresuid(getuid(), (e), geteuid())
#else
#ifdef HAVE_SETREUID
#define do_seteuid(e) setreuid(geteuid(), (e))
#else
#define do_seteuid(e) (errno = EPERM, -1)
#endif
#endif
#endif

#ifndef O_SYNC
#define O_SYNC 0
#endif

KRB5_DLLIMP int KRB5_CALLCONV
in_tkt(pname,pinst)
    char *pname;
    char *pinst;
{
    int tktfile;
    uid_t me, metoo, getuid(), geteuid();
    struct stat buf;
    int count;
    char *file = TKT_FILE;
    int fd;
    register int i;
    char charbuf[BUFSIZ];
    int mask;
#ifdef TKT_SHMEM
    char shmidname[MAXPATHLEN];
#endif /* TKT_SHMEM */

    /* If ticket cache selector is null, use default cache.  */
    if (file == 0)
	file = tkt_string();

    me = getuid ();
    metoo = geteuid();
    if (lstat(file,&buf) == 0) {
	if (buf.st_uid != me || !(buf.st_mode & S_IFREG) ||
	    buf.st_mode & 077) {
	    if (krb_debug)
		fprintf(stderr,"Error initializing %s",file);
	    return(KFAILURE);
	}
	/* file already exists, and permissions appear ok, so nuke it */
	if ((fd = open(file, O_RDWR|O_SYNC, 0)) < 0)
	    goto out; /* can't zero it, but we can still try truncating it */

	memset(charbuf, 0, sizeof(charbuf));

	for (i = 0; i < buf.st_size; i += sizeof(charbuf))
	    if (write(fd, charbuf, sizeof(charbuf)) != sizeof(charbuf)) {
#ifndef NO_FSYNC
		(void) fsync(fd);
#endif
		(void) close(fd);
		goto out;
	    }
	
#ifndef NO_FSYNC
	(void) fsync(fd);
#endif
	(void) close(fd);
    }
 out:
    /* arrange so the file is owned by the ruid
       (swap real & effective uid if necessary).
       This isn't a security problem, since the ticket file, if it already
       exists, has the right uid (== ruid) and mode. */
    if (me != metoo) {
	if (do_seteuid(me) < 0) {
	    /* can't switch??? barf! */
	    if (krb_debug)
		perror("in_tkt: seteuid");
	    return(KFAILURE);
	} else
	    if (krb_debug)
		printf("swapped UID's %d and %d\n",metoo,me);
    }
    /* Set umask to ensure that we have write access on the created
       ticket file.  */
    mask = umask(077);
    if ((tktfile = creat(file,0600)) < 0) {
	umask(mask);
	if (krb_debug)
	    fprintf(stderr,"Error initializing %s",TKT_FILE);
        return(KFAILURE);
    }
    umask(mask);
    if (me != metoo) {
	if (do_seteuid(metoo) < 0) {
	    /* can't switch??? barf! */
	    if (krb_debug)
		perror("in_tkt: seteuid2");
	    return(KFAILURE);
	} else
	    if (krb_debug)
		printf("swapped UID's %d and %d\n",me,metoo);
    }
    if (lstat(file,&buf) < 0) {
	if (krb_debug)
	    fprintf(stderr,"Error initializing %s",TKT_FILE);
        return(KFAILURE);
    }

    if (buf.st_uid != me || !(buf.st_mode & S_IFREG) ||
        buf.st_mode & 077) {
	if (krb_debug)
	    fprintf(stderr,"Error initializing %s",TKT_FILE);
        return(KFAILURE);
    }

    count = strlen(pname)+1;
    if (write(tktfile,pname,count) != count) {
        (void) close(tktfile);
        return(KFAILURE);
    }
    count = strlen(pinst)+1;
    if (write(tktfile,pinst,count) != count) {
        (void) close(tktfile);
        return(KFAILURE);
    }
    (void) close(tktfile);
#ifdef TKT_SHMEM
    (void) strcpy(shmidname, file);
    (void) strcat(shmidname, ".shm");
    return(krb_shm_create(shmidname));
#else /* !TKT_SHMEM */
    return(KSUCCESS);
#endif /* TKT_SHMEM */
}
