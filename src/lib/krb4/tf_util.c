/*
 * lib/krb4/tf_util.c
 *
 * Copyright 1985, 1986, 1987, 1988, 2000, 2001, 2007 by the Massachusetts
 * Institute of Technology.  All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

#include "krb.h"
#include "k5-int.h"
#include "krb4int.h"


#include <stdio.h>
#include <string.h>
#include <errno.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/stat.h>
#include <fcntl.h>

#ifdef TKT_SHMEM
#include <sys/param.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#endif /* TKT_SHMEM */



#define TOO_BIG -1
#define TF_LCK_RETRY ((unsigned)2)	/* seconds to sleep before
					 * retry if ticket file is
					 * locked */
extern int krb_debug;

void tf_close();

#ifdef TKT_SHMEM
char *krb_shm_addr;
static char *tmp_shm_addr;
static const char krb_dummy_skey[8];

char *shmat();
#endif /* TKT_SHMEM */

#ifdef NEED_UTIMES

#include <sys/time.h>
#ifdef __SCO__
#include <utime.h>
#endif
#if defined(__svr4__) || defined(__SVR4)
#include <utime.h>
#endif
int utimes(path, times)
     char* path;
     struct timeval times[2];
{
  struct utimbuf tv;
  tv.actime = times[0].tv_sec;
  tv.modtime = times[1].tv_sec;
  return utime(path,&tv);
}
#endif

#ifdef HAVE_SETEUID
#define do_seteuid(e) seteuid((e))
#else
#ifdef HAVE_SETRESUID
#define do_seteuid(e) setresuid(-1, (e), -1)
#else
#ifdef HAVE_SETREUID
#define do_seteuid(e) setreuid(geteuid(), (e))
#else
#define do_seteuid(e) (errno = EPERM, -1)
#endif
#endif
#endif


#ifdef K5_LE
/* This was taken from jhutz's patch for heimdal krb4. It only
 * applies to little endian systems. Big endian systems have a
 * less elegant solution documented below.
 *
 * This record is written after every real ticket, to ensure that
 * both 32- and 64-bit readers will perceive the next real ticket
 * as starting in the same place.  This record looks like a ticket
 * with the following properties:
 *   Field         32-bit             64-bit
 *   ============  =================  =================
 *   sname         "."                "."
 *   sinst         ""                 ""
 *   srealm        ".."               ".."
 *   session key   002E2E00 xxxxxxxx  xxxxxxxx 00000000
 *   lifetime      0                  0
 *   kvno          0                  12
 *   ticket        12 nulls           4 nulls
 *   issue         0                  0
 *
 * Our code always reads and writes the 32-bit format, but knows
 * to skip 00000000 at the front of a record, and to completely
 * ignore tickets for the special alignment principal.
 */
static unsigned char align_rec[] = {
    0x2e, 0x00, 0x00, 0x2e, 0x2e, 0x00, 0x00, 0x2e,
    0x2e, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00,
    0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00
};

#else /* Big Endian */

/* These alignment records are for big endian systems. We need more
 * of them because the portion of the 64-bit issue_date that overlaps
 * with the start of a ticket on 32-bit systems contains an unpredictable
 * number of NULL bytes. Preceeding these records is a second copy of the
 * 32-bit issue_date. The srealm for the alignment records is always one of
 * ".." or "?.."
 */

/* No NULL bytes
 * This is actually two alignment records since both 32- and 64-bit
 * readers will agree on everything in the first record up through the
 * issue_date size, except where sname starts.
 *   Field (1)     32-bit             64-bit
 *   ============  =================  =================
 *   sname         "????."            "."
 *   sinst         ""                 ""
 *   srealm        ".."               ".."
 *   session key   00000000 xxxxxxxx  00000000 xxxxxxxx
 *   lifetime      0                  0
 *   kvno          0                  0
 *   ticket        4 nulls           4 nulls
 *   issue         0                  0
 *
 *   Field (2)     32-bit             64-bit
 *   ============  =================  =================
 *   sname         "."                "."
 *   sinst         ""                 ""
 *   srealm        ".."               ".."
 *   session key   002E2E00 xxxxxxxx  xxxxxxxx 00000000
 *   lifetime      0                  0
 *   kvno          0                  12
 *   ticket        12 nulls           4 nulls
 *   issue         0                  0
 *
 */
static unsigned char align_rec_0[] = {
    0x2e, 0x00, 0x00, 0x2e, 0x2e, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x2e, 0x00, 0x00, 0x2e, 0x2e, 0x00,
    0x00, 0x2e, 0x2e, 0x00, 0xff, 0xff, 0xff, 0xff,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x04,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
};

/* One NULL byte
 *   Field         32-bit             64-bit
 *   ============  =================  =================
 *   sname         "x"  |"xx"|"xxx"   "."
 *   sinst         "xx."|"x."|"."     ".."
 *   srealm        ".."               "..."
 *   session key   2E2E2E00 xxxxxxxx  xxxxxxxx 00000000
 *   lifetime      0                  0
 *   kvno          0                  12
 *   ticket        12 nulls           4 nulls
 *   issue         0                  0
 */
static unsigned char align_rec_1[] = {
    0x2e, 0x00, 0x2e, 0x2e, 0x00, 0x2e, 0x2e, 0x2e,
    0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0c, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00
};

/* Two NULL bytes
 *   Field         32-bit             64-bit
 *   ============  =================  =================
 *   sname         "x"  |"x" |"xx"    ".."
 *   sinst         ""   |"x" |""      ""
 *   srealm        "x.."|".."|".."    ".."
 *   session key   002E2E00 xxxxxxxx  xxxxxxxx 00000000
 *   lifetime      0                  0
 *   kvno          0                  12
 *   ticket        12 nulls           4 nulls
 *   issue         0                  0
 */
 static unsigned char align_rec_2[] = {
    0x2e, 0x2e, 0x00, 0x00, 0x2e, 0x2e, 0x00, 0xff,
    0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00,
    0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* Three NULL bytes
 * Things break here for 32-bit krb4 libraries that don't
 * understand this alignment record. We can't really do
 * anything about the fact that the three strings ended
 * in the duplicate timestamp. The good news is that this
 * only happens once every 0x1000000 seconds, once roughly
 * every six and a half months. We'll live.
 *
 * Discussion on the krbdev list has suggested the
 * issue_date be incremented by one in this case to avoid
 * the problem. I'm leaving this here just in case.
 *
 *   Field         32-bit             64-bit
 *   ============  =================  =================
 *   sname         ""                 "."
 *   sinst         ""                 ""
 *   srealm        ""                 ".."
 *   session key   2E00002E 2E00FFFF  xxxx0000 0000xxxx
 *   lifetime      0                  0
 *   kvno          4294901760         917504
 *   ticket        14 nulls           4 nulls
 *   issue         0                  0
 */
/*
static unsigned char align_rec_3[] = {
    0x2e, 0x00, 0x00, 0x2e, 0x2e, 0x00, 0xff, 0xff,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
*/
#endif /* K5_LE*/

/*
 * fd must be initialized to something that won't ever occur as a real
 * file descriptor. Since open(2) returns only non-negative numbers as
 * valid file descriptors, and tf_init always stuffs the return value
 * from open in here even if it is an error flag, we must
 * 	a. Initialize fd to a negative number, to indicate that it is
 * 	   not initially valid.
 *	b. When checking for a valid fd, assume that negative values
 *	   are invalid (ie. when deciding whether tf_init has been
 *	   called.)
 *	c. In tf_close, be sure it gets reinitialized to a negative
 *	   number. 
 */
static int  fd = -1;
static int  curpos;			/* Position in tfbfr */
static int  lastpos;			/* End of tfbfr */
static char tfbfr[BUFSIZ];		/* Buffer for ticket data */

static int tf_gets (char *, int), tf_read (char *, int);

/*
 * This file contains routines for manipulating the ticket cache file.
 *
 * The ticket file is in the following format:
 *
 *      principal's name        (null-terminated string)
 *      principal's instance    (null-terminated string)
 *      CREDENTIAL_1
 *      CREDENTIAL_2
 *      ...
 *      CREDENTIAL_n
 *      EOF
 *
 *      Where "CREDENTIAL_x" consists of the following fixed-length
 *      fields from the CREDENTIALS structure (see "krb.h"):
 *
 *              string          service[ANAME_SZ]
 *              string          instance[INST_SZ]
 *              string          realm[REALM_SZ]
 *              C_Block         session
 *              int             lifetime
 *              int             kvno
 *              KTEXT_ST        ticket_st
 *              KRB4_32         issue_date
 *
 * Strings are stored NUL-terminated, and read back until a NUL is
 * found or the indicated number of bytes have been read.  (So if you
 * try to store a string exactly that long or longer, reading them
 * back will not work.)  The KTEXT_ST structure is stored as an int
 * length followed by that many data bytes.  All ints are stored using
 * host size and byte order for "int".
 *
 * Short description of routines:
 *
 * tf_init() opens the ticket file and locks it.
 *
 * tf_get_pname() returns the principal's name.
 *
 * tf_get_pinst() returns the principal's instance (may be null).
 *
 * tf_get_cred() returns the next CREDENTIALS record.
 *
 * tf_save_cred() appends a new CREDENTIAL record to the ticket file.
 *
 * tf_close() closes the ticket file and releases the lock.
 *
 * tf_gets() returns the next null-terminated string.  It's an internal
 * routine used by tf_get_pname(), tf_get_pinst(), and tf_get_cred().
 *
 * tf_read() reads a given number of bytes.  It's an internal routine
 * used by tf_get_cred().
 */

/*
 * tf_init() should be called before the other ticket file routines.
 * It takes the name of the ticket file to use, "tf_name", and a
 * read/write flag "rw" as arguments. 
 *
 * It tries to open the ticket file, checks the mode, and if everything
 * is okay, locks the file.  If it's opened for reading, the lock is
 * shared.  If it's opened for writing, the lock is exclusive. 
 *
 * Returns KSUCCESS if all went well, otherwise one of the following: 
 *
 * NO_TKT_FIL   - file wasn't there
 * TKT_FIL_ACC  - file was in wrong mode, etc.
 * TKT_FIL_LCK  - couldn't lock the file, even after a retry
 */

int KRB5_CALLCONV tf_init(tf_name, rw)
    const char   *tf_name;
    int rw;
{
    int     wflag;
    uid_t   me, metoo;
    struct stat stat_buf, stat_buffd;
#ifdef TKT_SHMEM
    char shmidname[MAXPATHLEN]; 
    FILE *sfp;
    int shmid;
#endif

    if (!krb5__krb4_context) {
	    if (krb5_init_context(&krb5__krb4_context))
		    return TKT_FIL_LCK;
    }

    me = getuid();
    metoo = geteuid();

    switch (rw) {
    case R_TKT_FIL:
	wflag = 0;
	break;
    case W_TKT_FIL:
	wflag = 1;
	break;
    default:
	if (krb_debug) fprintf(stderr, "tf_init: illegal parameter\n");
	return TKT_FIL_ACC;
    }

    /* If ticket cache selector is null, use default cache.  */
    if (tf_name == 0)
	tf_name = tkt_string();

#ifdef TKT_SHMEM
    (void) strncpy(shmidname, tf_name, sizeof(shmidname) - 1);
    shmidname[sizeof(shmidname) - 1] = '\0';
    (void) strncat(shmidname, ".shm", sizeof(shmidname) - 1 - strlen(shmidname));
#endif /* TKT_SHMEM */

    /*
     * If "wflag" is set, open the ticket file in append-writeonly mode
     * and lock the ticket file in exclusive mode.  If unable to lock
     * the file, sleep and try again.  If we fail again, return with the
     * proper error message. 
     */

    curpos = sizeof(tfbfr);

#ifdef TKT_SHMEM
    if (lstat(shmidname, &stat_buf) < 0) {
	switch (errno) {
	case ENOENT:
	    return NO_TKT_FIL;
	default:
	    return TKT_FIL_ACC;
	}
    }
    if (stat_buf.st_uid != me || !(stat_buf.st_mode & S_IFREG)
	|| stat_buf.st_nlink != 1 || stat_buf.st_mode & 077) {
	return TKT_FIL_ACC;
    }

    /*
     * Yes, we do uid twiddling here.  It's not optimal, but some
     * applications may expect that the ruid is what should really own
     * the ticket file, e.g. setuid applications.
     */
    if (me != metoo && do_seteuid(me) < 0)
	return KFAILURE;
    sfp = fopen(shmidname, "r");	/* only need read/write on the
					   actual tickets */
    if (sfp != 0)
	set_cloexec_file(sfp);
    if (me != metoo && do_seteuid(metoo) < 0)
	return KFAILURE;
    if (sfp == 0) {
        switch(errno) {
        case ENOENT:
	    return NO_TKT_FIL;
	default:
	    return TKT_FIL_ACC;
	}
    }

    /*
     * fstat() the file to check that the file we opened is the one we
     * think it is.
     */
    if (fstat(fileno(sfp), &stat_buffd) < 0) {
        (void) close(fd);
	fd = -1;
	switch(errno) {
	case ENOENT:
	    return NO_TKT_FIL;
	default:
	    return TKT_FIL_ACC;
	}
    }
    /* Check that it's the right file */
    if ((stat_buf.st_ino != stat_buffd.st_ino) ||
	(stat_buf.st_dev != stat_buffd.st_dev)) {
        (void) close(fd);
	fd = -1;
	return TKT_FIL_ACC;
    }
    /* Check ownership */
    if ((stat_buffd.st_uid != me && me != 0) ||
	((stat_buffd.st_mode & S_IFMT) != S_IFREG)) {
        (void) close(fd);
	fd = -1;
	return TKT_FIL_ACC;
    }



    shmid = -1;
    {
	char buf[BUFSIZ];
	int val;			/* useful for debugging fscanf */
	/* We provide our own buffer here since some STDIO libraries
	   barf on unbuffered input with fscanf() */
	setbuf(sfp, buf);
	if ((val = fscanf(sfp,"%d",&shmid)) != 1) {
	    (void) fclose(sfp);
	    return TKT_FIL_ACC;
	}
	if (shmid < 0) {
	    (void) fclose(sfp);
	    return TKT_FIL_ACC;
	}
	(void) fclose(sfp);
    }
    /*
    * global krb_shm_addr is initialized to 0.  Ultrix bombs when you try and
    * attach the same segment twice so we need this check.
    */
    if (!krb_shm_addr) {
    	if ((krb_shm_addr = shmat(shmid,0,0)) == -1){
		if (krb_debug)
		    fprintf(stderr,
			    "cannot attach shared memory for segment %d\n",
			    shmid);
		krb_shm_addr = 0;	/* reset so we catch further errors */
		return TKT_FIL_ACC;
	    }
    }
    tmp_shm_addr = krb_shm_addr;
#endif /* TKT_SHMEM */
    
    if (lstat(tf_name, &stat_buf) < 0) {
	switch (errno) {
	case ENOENT:
	    return NO_TKT_FIL;
	default:
	    return TKT_FIL_ACC;
	}
    }
    if (stat_buf.st_uid != me || !(stat_buf.st_mode & S_IFREG)
	|| stat_buf.st_nlink != 1 || stat_buf.st_mode & 077) {
	return TKT_FIL_ACC;
    }

    if (wflag) {
	if (me != metoo && do_seteuid(me) < 0)
	    return KFAILURE;
	fd = open(tf_name, O_RDWR, 0600);
	if (fd >= 0)
	    set_cloexec_fd(fd);
	if (me != metoo && do_seteuid(metoo) < 0)
	    return KFAILURE;
	if (fd < 0) {
	    switch(errno) {
	    case ENOENT:
	        return NO_TKT_FIL;
	    default:
	        return TKT_FIL_ACC;
	  }
	}
	/*
	 * fstat() the file to check that the file we opened is the
	 * one we think it is, and to check ownership.
	 */
	if (fstat(fd, &stat_buffd) < 0) {
	    (void) close(fd);
	    fd = -1;
	    switch(errno) {
	    case ENOENT:
	        return NO_TKT_FIL;
	    default:
	        return TKT_FIL_ACC;
	    }
	}
	/* Check that it's the right file */
	if ((stat_buf.st_ino != stat_buffd.st_ino) ||
	    (stat_buf.st_dev != stat_buffd.st_dev)) {
	    (void) close(fd);
	    fd = -1;
	    return TKT_FIL_ACC;
	}
	/* Check ownership */
	if ((stat_buffd.st_uid != me && me != 0) ||
	    ((stat_buffd.st_mode & S_IFMT) != S_IFREG)) {
	    (void) close(fd);
	    fd = -1;
	    return TKT_FIL_ACC;
	}
	if (krb5_lock_file(krb5__krb4_context, fd,
			   KRB5_LOCKMODE_EXCLUSIVE |
			   KRB5_LOCKMODE_DONTBLOCK) < 0) {
	    sleep(TF_LCK_RETRY);
	    if (krb5_lock_file(krb5__krb4_context, fd,
			   KRB5_LOCKMODE_EXCLUSIVE |
			   KRB5_LOCKMODE_DONTBLOCK) < 0) {
		(void) close(fd);
		fd = -1;
		return TKT_FIL_LCK;
	    }
	}
	return KSUCCESS;
    }
    /*
     * Otherwise "wflag" is not set and the ticket file should be opened
     * for read-only operations and locked for shared access. 
     */

    if (me != metoo && do_seteuid(me) < 0)
	return KFAILURE;
    fd = open(tf_name, O_RDONLY, 0600);
    if (fd >= 0)
	set_cloexec_fd(fd);
    if (me != metoo && do_seteuid(metoo) < 0)
	return KFAILURE;
    if (fd < 0) {
        switch(errno) {
	case ENOENT:
	    return NO_TKT_FIL;
	default:
	    return TKT_FIL_ACC;
	}
    }
    /*
     * fstat() the file to check that the file we opened is the one we
     * think it is, and to check ownership.
     */
    if (fstat(fd, &stat_buffd) < 0) {
        (void) close(fd);
	fd = -1;
	switch(errno) {
	case ENOENT:
	    return NO_TKT_FIL;
	default:
	    return TKT_FIL_ACC;
	}
    }
    /* Check that it's the right file */
    if ((stat_buf.st_ino != stat_buffd.st_ino) ||
	(stat_buf.st_dev != stat_buffd.st_dev)) {
        (void) close(fd);
	fd = -1;
	return TKT_FIL_ACC;
    }
    /* Check ownership */
    if ((stat_buffd.st_uid != me && me != 0) ||
	((stat_buffd.st_mode & S_IFMT) != S_IFREG)) {
        (void) close(fd);
	fd = -1;
	return TKT_FIL_ACC;
    }
    if (krb5_lock_file(krb5__krb4_context, fd,
			   KRB5_LOCKMODE_SHARED |
			   KRB5_LOCKMODE_DONTBLOCK) < 0) {
	sleep(TF_LCK_RETRY);
	if (krb5_lock_file(krb5__krb4_context, fd,
			   KRB5_LOCKMODE_SHARED |
			   KRB5_LOCKMODE_DONTBLOCK) < 0) {
	    (void) close(fd);
	    fd = -1;
	    return TKT_FIL_LCK;
	}
    }
    return KSUCCESS;
}

/*
 * tf_get_pname() reads the principal's name from the ticket file. It
 * should only be called after tf_init() has been called.  The
 * principal's name is filled into the "p" parameter.  If all goes well,
 * KSUCCESS is returned.  If tf_init() wasn't called, TKT_FIL_INI is
 * returned.  If the name was null, or EOF was encountered, or the name
 * was longer than ANAME_SZ, TKT_FIL_FMT is returned. 
 */

int KRB5_CALLCONV tf_get_pname(p)
    char   *p;
{
    if (fd < 0) {
	if (krb_debug)
	    fprintf(stderr, "tf_get_pname called before tf_init.\n");
	return TKT_FIL_INI;
    }
    if (tf_gets(p, ANAME_SZ) < 2)	/* can't be just a null */
	return TKT_FIL_FMT;
    return KSUCCESS;
}

/*
 * tf_get_pinst() reads the principal's instance from a ticket file.
 * It should only be called after tf_init() and tf_get_pname() have been
 * called.  The instance is filled into the "inst" parameter.  If all
 * goes well, KSUCCESS is returned.  If tf_init() wasn't called,
 * TKT_FIL_INI is returned.  If EOF was encountered, or the instance
 * was longer than ANAME_SZ, TKT_FIL_FMT is returned.  Note that the
 * instance may be null. 
 */

int KRB5_CALLCONV tf_get_pinst(inst)
    char   *inst;
{
    if (fd < 0) {
	if (krb_debug)
	    fprintf(stderr, "tf_get_pinst called before tf_init.\n");
	return TKT_FIL_INI;
    }
    if (tf_gets(inst, INST_SZ) < 1)
	return TKT_FIL_FMT;
    return KSUCCESS;
}

/*
 * tf_get_cred() reads a CREDENTIALS record from a ticket file and fills
 * in the given structure "c".  It should only be called after tf_init(),
 * tf_get_pname(), and tf_get_pinst() have been called. If all goes well,
 * KSUCCESS is returned.  Possible error codes are: 
 *
 * TKT_FIL_INI  - tf_init wasn't called first
 * TKT_FIL_FMT  - bad format
 * EOF          - end of file encountered
 */

static int  real_tf_get_cred(c)
    CREDENTIALS *c;
{
    KTEXT   ticket = &c->ticket_st;	/* pointer to ticket */
    int     k_errno;
    unsigned char nullbuf[3];  /* used for 64-bit issue_date tf compatibility */

    if (fd < 0) {
	if (krb_debug)
	    fprintf(stderr, "tf_get_cred called before tf_init.\n");
	return TKT_FIL_INI;
    }
    if ((k_errno = tf_gets(c->service, SNAME_SZ)) < 2) {

#ifdef K5_BE
	/* If we're big endian then we can have a null service name as part of
	 * an alignment record. */
	if (k_errno < 2)
	    switch (k_errno) {
	    case TOO_BIG:
		tf_close();
		return TKT_FIL_FMT;
	    case 0:
		return EOF;
	    }
#else /* Little Endian */
	/* If we read an empty service name, it's possible that's because
	 * the file was written by someone who thinks issue_date should be
	 * 64 bits.  If that is the case, there will be three more zeros,
	 * followed by the real record.*/

	if (k_errno == 1 && 
	    tf_read(nullbuf, 3) == 3 &&
	    !nullbuf[0] && !nullbuf[1] && !nullbuf[2])
	    k_errno = tf_gets(c->service, SNAME_SZ);

	if (k_errno < 2)
	switch (k_errno) {
	case TOO_BIG:
	case 1:		/* can't be just a null */
	    tf_close();
	    return TKT_FIL_FMT;
	case 0:
	    return EOF;
	}
#endif/*K5_BE*/

    }
    if ((k_errno = tf_gets(c->instance, INST_SZ)) < 1)
	switch (k_errno) {
	case TOO_BIG:
	    return TKT_FIL_FMT;
	case 0:
	    return EOF;
	}
    if ((k_errno = tf_gets(c->realm, REALM_SZ)) < 2) {
	switch (k_errno) {
	case TOO_BIG:
	case 1:		/* can't be just a null */
	    tf_close();
	    return TKT_FIL_FMT;
	case 0:
	    return EOF;
	}
    }
    
    if (
	tf_read((char *) (c->session), KEY_SZ) < 1 ||
	tf_read((char *) &(c->lifetime), sizeof(c->lifetime)) < 1 ||
	tf_read((char *) &(c->kvno), sizeof(c->kvno)) < 1 ||
	tf_read((char *) &(ticket->length), sizeof(ticket->length))
	< 1 ||
    /* don't try to read a silly amount into ticket->dat */
	ticket->length > MAX_KTXT_LEN ||
	tf_read((char *) (ticket->dat), ticket->length) < 1 ||
	tf_read((char *) &(c->issue_date), sizeof(c->issue_date)) < 1
	) {
	tf_close();
	return TKT_FIL_FMT;
    }

#ifdef K5_BE
    /* If the issue_date is 0 and we're not dealing with an alignment
       record, then it's likely we've run into an issue_date written by
       a 64-bit library that is using long instead of KRB4_32. Let's get
       the next four bytes instead.
     */
    if (0 == c->issue_date) {
	int len = strlen(c->realm);
	if (!(2 == len && 0 == strcmp(c->realm, "..")) &&
	    !(3 == len && 0 == strcmp(c->realm + 1, ".."))) {
	    if (tf_read((char *) &(c->issue_date), sizeof(c->issue_date)) < 1) {
		tf_close();
		return TKT_FIL_FMT;
	    }
	}
    }

#endif
    
    return KSUCCESS;
}

int KRB5_CALLCONV tf_get_cred(c)
    CREDENTIALS *c;
{
    int     k_errno;
    int     fake;
    
    do {
	fake = 0;
	k_errno = real_tf_get_cred(c);
	if (k_errno)
	    return k_errno;
	
#ifdef K5_BE
	/* Here we're checking to see if the realm is one of the 
	 * alignment record realms, ".." or "?..", so we can skip it.
	 * If it's not, then we need to verify that the service name
	 * was not null as this should be a valid ticket.
	 */
	{
	    int len = strlen(c->realm);
	    if (2 == len && 0 == strcmp(c->realm, ".."))
		fake = 1;
	    if (3 == len && 0 == strcmp(c->realm + 1, ".."))
		fake = 1;
	    if (!fake && 0 == strlen(c->service)) {
		tf_close();
		return TKT_FIL_FMT;
	    }
	}
#else /* Little Endian */
	/* Here we're checking to see if the service principal is the
	 * special alignment record principal ".@..", so we can skip it.
	 */
	if (strcmp(c->service, ".") == 0 &&
	    strcmp(c->instance, "") == 0 &&
	    strcmp(c->realm, "..") == 0)
	    fake = 1;
#endif/*K5_BE*/
    } while (fake);
    
#ifdef TKT_SHMEM
    memcpy(c->session, tmp_shm_addr, KEY_SZ);
    tmp_shm_addr += KEY_SZ;
#endif /* TKT_SHMEM */
    return KSUCCESS;
}

/*
 * tf_close() closes the ticket file and sets "fd" to -1. If "fd" is
 * not a valid file descriptor, it just returns.  It also clears the
 * buffer used to read tickets.
 *
 * The return value is not defined.
 */

void KRB5_CALLCONV tf_close()
{
    if (!(fd < 0)) {
#ifdef TKT_SHMEM
	if (shmdt(krb_shm_addr)) {
	    /* what kind of error? */
	    if (krb_debug)
		fprintf(stderr, "shmdt 0x%x: errno %d",krb_shm_addr, errno);
	} else {
	    krb_shm_addr = 0;
	}
#endif /* TKT_SHMEM */
	if (!krb5__krb4_context)
		krb5_init_context(&krb5__krb4_context);
	(void) krb5_lock_file(krb5__krb4_context, fd, KRB5_LOCKMODE_UNLOCK);
	(void) close(fd);
	fd = -1;		/* see declaration of fd above */
    }
    memset(tfbfr, 0, sizeof(tfbfr));
}

/*
 * tf_gets() is an internal routine.  It takes a string "s" and a count
 * "n", and reads from the file until either it has read "n" characters,
 * or until it reads a null byte. When finished, what has been read exists
 * in "s". If it encounters EOF or an error, it closes the ticket file. 
 *
 * Possible return values are:
 *
 * n            the number of bytes read (including null terminator)
 *              when all goes well
 *
 * 0            end of file or read error
 *
 * TOO_BIG      if "count" characters are read and no null is
 *		encountered. This is an indication that the ticket
 *		file is seriously ill.
 */

static int
tf_gets(s, n)
    register char *s;
    int n;
{
    register int count;

    if (fd < 0) {
	if (krb_debug)
	    fprintf(stderr, "tf_gets called before tf_init.\n");
	return TKT_FIL_INI;
    }
    for (count = n - 1; count > 0; --count) {
	if (curpos >= sizeof(tfbfr)) {
	    lastpos = read(fd, tfbfr, sizeof(tfbfr));
	    curpos = 0;
	}
	if (curpos == lastpos) {
	    tf_close();
	    return 0;
	}
	*s = tfbfr[curpos++];
	if (*s++ == '\0')
	    return (n - count);
    }
    tf_close();
    return TOO_BIG;
}

/*
 * tf_read() is an internal routine.  It takes a string "s" and a count
 * "n", and reads from the file until "n" bytes have been read.  When
 * finished, what has been read exists in "s".  If it encounters EOF or
 * an error, it closes the ticket file.
 *
 * Possible return values are:
 *
 * n		the number of bytes read when all goes well
 *
 * 0		on end of file or read error
 */

static int
tf_read(s, n)
    register char *s;
    register int  n;
{
    register int count;
    
    for (count = n; count > 0; --count) {
	if (curpos >= sizeof(tfbfr)) {
	    lastpos = read(fd, tfbfr, sizeof(tfbfr));
	    curpos = 0;
	}
	if (curpos == lastpos) {
	    tf_close();
	    return 0;
	}
	*s++ = tfbfr[curpos++];
    }
    return n;
}
     
/*
 * tf_save_cred() appends an incoming ticket to the end of the ticket
 * file.  You must call tf_init() before calling tf_save_cred().
 *
 * The "service", "instance", and "realm" arguments specify the
 * server's name; "session" contains the session key to be used with
 * the ticket; "kvno" is the server key version number in which the
 * ticket is encrypted, "ticket" contains the actual ticket, and
 * "issue_date" is the time the ticket was requested (local host's time).
 *
 * Returns KSUCCESS if all goes well, TKT_FIL_INI if tf_init() wasn't
 * called previously, and KFAILURE for anything else that went wrong.
 */

int tf_save_cred(service, instance, realm, session, lifetime, kvno,
		 ticket, issue_date)
    char   *service;		/* Service name */
    char   *instance;		/* Instance */
    char   *realm;		/* Auth domain */
    C_Block session;		/* Session key */
    int     lifetime;		/* Lifetime */
    int     kvno;		/* Key version number */
    KTEXT   ticket;		/* The ticket itself */
    KRB4_32 issue_date;		/* The issue time */
{

    off_t   lseek();
    unsigned int count;		/* count for write */
#ifdef TKT_SHMEM
    int	    *skey_check;
#endif /* TKT_SHMEM */

    if (fd < 0) {		/* fd is ticket file as set by tf_init */
	  if (krb_debug)
	      fprintf(stderr, "tf_save_cred called before tf_init.\n");
	  return TKT_FIL_INI;
    }
    /* Find the end of the ticket file */
    (void) lseek(fd, (off_t)0, 2);
#ifdef TKT_SHMEM
    /* scan to end of existing keys: pick first 'empty' slot.
       we assume that no real keys will be completely zero (it's a weak
       key under DES) */

    skey_check = (int *) krb_shm_addr;

    while (*skey_check && *(skey_check+1))
	skey_check += 2;
    tmp_shm_addr = (char *)skey_check;
#endif /* TKT_SHMEM */

    /* Write the ticket and associated data */
    /* Service */
    count = strlen(service) + 1;
    if (write(fd, service, count) != count)
	goto bad;
    /* Instance */
    count = strlen(instance) + 1;
    if (write(fd, instance, count) != count)
	goto bad;
    /* Realm */
    count = strlen(realm) + 1;
    if (write(fd, realm, count) != count)
	goto bad;
    /* Session key */
#ifdef TKT_SHMEM
    memcpy(tmp_shm_addr, session, 8);
    tmp_shm_addr+=8;
    if (write(fd,krb_dummy_skey,8) != 8)
	goto bad;
#else /* ! TKT_SHMEM */
    if (write(fd, (char *) session, 8) != 8)
	goto bad;
#endif /* TKT_SHMEM */
    /* Lifetime */
    if (write(fd, (char *) &lifetime, sizeof(int)) != sizeof(int))
	goto bad;
    /* Key vno */
    if (write(fd, (char *) &kvno, sizeof(int)) != sizeof(int))
	goto bad;
    /* Tkt length */
    if (write(fd, (char *) &(ticket->length), sizeof(int)) !=
	sizeof(int))
	goto bad;
    /* Ticket */
    count = ticket->length;
    if (write(fd, (char *) (ticket->dat), count) != count)
	goto bad;
    /* Issue date */
    if (write(fd, (char *) &issue_date, sizeof(KRB4_32))
	!= sizeof(KRB4_32))
	goto bad;
    /* Alignment Record */
#ifdef K5_BE
    {
	int null_bytes = 0;
	if (0 == (issue_date & 0xff000000))
	    ++null_bytes;
	if (0 == (issue_date & 0x00ff0000))
	    ++null_bytes;
	if (0 == (issue_date & 0x0000ff00))
	    ++null_bytes;
	if (0 == (issue_date & 0x000000ff))
	    ++null_bytes;
	
	switch(null_bytes) {
	case 0:
	    /* Issue date */
	    if (write(fd, (char *) &issue_date, sizeof(KRB4_32))
		!= sizeof(KRB4_32))
	goto bad;
	    if (write(fd, align_rec_0, sizeof(align_rec_0))
		!= sizeof(align_rec_0))
		goto bad;
	    break;
	    
	case 1:
	    if (write(fd, (char *) &issue_date, sizeof(KRB4_32))
		!= sizeof(KRB4_32))
		goto bad;
	    if (write(fd, align_rec_1, sizeof(align_rec_1))
		!= sizeof(align_rec_1))
		goto bad;
	    break;
	    
	case 3:
	    /* Three NULLS are troublesome but rare. We'll just pretend 
	     * they don't exist by decrementing the issue_date.
	     */
	    --issue_date;
	case 2:
	    if (write(fd, (char *) &issue_date, sizeof(KRB4_32))
		!= sizeof(KRB4_32))
		goto bad;
	    if (write(fd, align_rec_2, sizeof(align_rec_2))
		!= sizeof(align_rec_2))
		goto bad;
	    break;
	    
	default:
	    goto bad;
	}
	
    }    
#else
    if (write(fd, align_rec, sizeof(align_rec)) != sizeof(align_rec))
	goto bad;
#endif 

    /* Actually, we should check each write for success */
    return (KSUCCESS);
bad:
    return (KFAILURE);
}
