/*
 * dest_tkt.c
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
#include <fcntl.h>
#include <sys/stat.h>
#ifdef TKT_SHMEM
#include <sys/param.h>
#endif
#include <errno.h>

#ifndef O_SYNC
#define O_SYNC 0
#endif

/*
 * dest_tkt() is used to destroy the ticket store upon logout.
 * If the ticket file does not exist, dest_tkt() returns RET_TKFIL.
 * Otherwise the function returns RET_OK on success, KFAILURE on
 * failure.
 *
 * The ticket file (TKT_FILE) is defined in "krb.h".
 */

KRB5_DLLIMP int KRB5_CALLCONV
dest_tkt()
{
    char *file = TKT_FILE;
    int i,fd;
    extern int errno;
    struct stat statb;
    char buf[BUFSIZ];
#ifdef TKT_SHMEM
    char shmidname[MAXPATHLEN];
#endif /* TKT_SHMEM */

    /* If ticket cache selector is null, use default cache.  */
    if (file == 0)
	file = tkt_string();

    errno = 0;
    if (lstat(file,&statb) < 0)
	goto out;

    if (!(statb.st_mode & S_IFREG)
#ifdef notdef
	|| statb.st_mode & 077
#endif
	)
	goto out;

    if ((fd = open(file, O_RDWR|O_SYNC, 0)) < 0)
	goto out;

    memset(buf, 0, BUFSIZ);

    for (i = 0; i < statb.st_size; i += BUFSIZ)
	if (write(fd, buf, BUFSIZ) != BUFSIZ) {
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

    (void) unlink(file);

out:
    if (errno == ENOENT) return RET_TKFIL;
    else if (errno != 0) return KFAILURE;
#ifdef TKT_SHMEM
    /* 
     * handle the shared memory case 
     */
    (void) strncpy(shmidname, file, sizeof(shmidname) - 1);
    shmidname[sizeof(shmidname) - 1] = '\0';
    (void) strcat(shmidname, ".shm", sizeof(shmidname) - 1 - strlen(shmidname));
    if ((i = krb_shm_dest(shmidname)) != KSUCCESS)
	return(i);
#endif /* TKT_SHMEM */
    return(KSUCCESS);
}
