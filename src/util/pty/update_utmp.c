/*
 * pty_update_utmp: Update or create a utmp entry
 * 
 * Copyright 1995, 2001 by the Massachusetts Institute of Technology.
 * 
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and without fee is hereby
 * granted, provided that the above copyright notice appear in all
 * copies and that both that copyright notice and this permission
 * notice appear in supporting documentation, and that the name of
 * M.I.T. not be used in advertising or publicity pertaining to
 * distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability
 * of this software for any purpose.  It is provided "as is" without
 * express or implied warranty.
 */

/*
 * Rant about the historical vagaries of utmp:
 * -------------------------------------------
 *
 * There exist many subtly incompatible incarnations of utmp, ranging
 * from BSD to System V to Unix98 and everywhere in between.  This
 * rant attempts to collect in one place as much knowledge as possible
 * about this portability nightmare.
 *
 * BSD:
 * ----
 *
 * The simplest (and earliest?) case is 4.x BSD utmp/wtmp.  There are
 * no auxiliary files.  There is only a struct utmp, declared in
 * utmp.h.  Its contents usually include:
 *
 *	char ut_line[]
 *	char ut_name[]
 *	char ut_host[]
 *	long ut_time
 *
 * The meanings of these fields follows their names reasonbly well.
 * The ut_line field usually is the pathname of the tty device
 * associated with the login, with the leading "/dev/" stripped off.
 *
 * It is believed that ut_host is nul-terminated, while the other
 * strings are merely nul-padded.
 *
 * Generally, ut_name is an empty string for a logout record in both
 * utmp and wtmp.  For entries made by the window system or other
 * terminal emulation stuff, ut_host is an empty string (at least
 * under SunOS 4.x, it seems).  The macro nonuser() is used to
 * determine this if a utmp entry is made by the window system on at
 * least SunOS 4.x.
 *
 * It is not know whether the login program or init is responsible for
 * clearing the utmp entry, or for entering a logout record in wtmp.
 * It is likely the case that init cleans up for processes that it is
 * itself responsible for starting.
 *
 * Old (c. 1984) System V:
 * -----------------------
 *
 * This is partially conjecture, based on some reading of
 * /usr/xpg2include/utmp.h on a SunOS 4.x system.  There appears to
 * only be a struct utmp, declared in utmp.h.  It is likely used for
 * both utmp and wtmp files.  It is quite likely that the utmp is only
 * supposed to be accessed via the getutline()/pututline() API.  The
 * contents of struct utmp seem to include:
 *
 *	char	ut_user[]
 *	char	ut_id[]
 *	char	ut_line[]
 *	short	ut_pid
 *	short	ut_type
 *	struct exit_status ut_exit
 *	time_t	ut_time
 *
 * On these systems, ut_name is often #define'ed to be ut_user to be
 * somewhat compatible with the BSD-style utmp.  Note that there is
 * not necessarily a ut_host field in this utmp structure.
 *
 * The ut_id field bears some explanation.  The systems that use this
 * style of utmp also use a sysV-ish init, which starts processes out
 * of /etc/inittab rather than /etc/ttys, and has the concept of
 * runlevels.  The first field in each line of /etc/inittab contains a
 * unique ID field.  init probably gets really confused if there are
 * conflicts here.  Every process that init starts gets its own entry
 * written to utmp.
 *
 * It is possible for multiple entries to have the same ut_line but
 * different ut_id values, since the sysadmin will be responsible for
 * assigning values to ut_id.  Usually, ut_id is four characters,
 * while the permissible unique ID values for entries in /etc/inittab
 * are constrained to two characters, but this is not always the
 * case.  In the case where we are emulating the vendor's login
 * program and being run out of getty, we need to account for which
 * value of ut_id was used by the getty, since pututline() will search
 * based on ut_id and not ut_line for some reason.
 *
 * The ut_pid and ut_type fields are used for bookkeeping by init.
 * The ut_type field gets the value INIT_PROCESS for processes started
 * by init.  It gets the value LOGIN_PROCESS if it is a process that
 * is prompting for a login name, and it gets the value USER_PROCESS
 * for an actual valid login.  When the process dies, either init
 * cleans up after it and records a DEAD_PROCESS entry in utmp, or the
 * process itself does so.  It's not completely clear which actually
 * happens, though it is quite possible that init only cleans up after
 * processes that it starts itself.
 *
 * Other values of ut_type exist; they're largely internal bookkeeping
 * for init's runlevels and such, and don't really interest this
 * library at all.
 *
 * The ut_exit field contains the following members:
 *
 *	short	e_termination
 *	short	e_exit
 *
 * It is not clear how these values are used; presumably they record
 * the process termination status of dead processes.
 *
 * There is no uniform API for manipulating wtmp on systems that use
 * this sort of utmp structure; it can be assumed that the structure
 * can be directly written to the wtmp file.
 *
 * Unix98:
 * -------
 *
 * This description also likely applies to later System V derivatives
 * as well as systems conforming to earlier X/Open standards such as
 * XPG4.  There is a new header, utmpx.h, which defines a struct utmpx
 * and a new getutxline()/pututxline() API for accessing it.  Some
 * systems actually have a utmpx file on disk; others use the utmpx
 * API to access a file named utmp, just to further confuse matters.
 *
 * The utmpx structure is guaranteed (by Unix98) to contain at least
 * the following:
 *
 *	char	ut_user[]
 *	char	ut_line[]
 *	char	ut_id[]
 *	pid_t	ut_pid
 *	short	ut_type
 *	struct timeval ut_tv
 *
 * It is not guaranteed to contain, but often does contain, the
 * following:
 *
 *	char	ut_host[]
 *	int	ut_syslen
 *	int	ut_session
 *	struct exit_status ut_exit
 *
 * The ut_syslen field, on systems that contain it, contains the
 * number of significant characters in ut_host, including the
 * terminating nul character.
 *
 * The main difference between this struct utmpx and the struct utmp
 * used by early sysV derivatives is the change from a time_t or long
 * for ut_time to a struct timeval for ut_tv.
 *
 * Comments in various header files imply that ut_session is used for
 * window systems, but it's not clear how.  Perhaps it contains the
 * session ID of the session running the window system, e.g. the xdm
 * or X server on an X11 system.
 *
 * Most of the description of the earlier sysV format probably applies
 * here, with suitable changes of names.  On systems that maintain
 * utmpx and utmp files in parallel, it is assumed that using the
 * pututxline() API is sufficient to keep them in sync.  There are no
 * known counterexamples to this.
 *
 * Nevertheless, there are, on some systems, API functions getutmp()
 * and getutmpx() that appear to convert from struct utmpx to struct
 * utmp and vice versa.  This could be useful when there is a wtmp
 * file but not a corresponding wtmpx file.
 *
 * Incidentally, ut_exit is sometimes present in the struct utmp but
 * not the struct utmpx for a given system.  Sometimes, it exists in
 * both, but contains differently named members.  It's probably one of
 * the least portable pieces in this whole mess.
 *
 * Known Quirks of Specific OSes:
 * ------------------------------
 *
 * Solaris 2.x:
 *
 * Has utmpd, which will automatically clean up utmpx, utmp, wtmpx,
 * wtmp after process termination, provided that pututxline() was
 * used.
 *
 * Solaris 8 seems to have a bug in utmpname() that causes
 * garbage filenames to be generated.  Solaris 7 (and possibly Solaris
 * 8) have a bug in utmpxname() that prevents them from looking at
 * anything other than /var/adm/utmpx, it seems.  For some reason,
 * though, utmpname() goes and looks at the corresponding utmpx file.
 *
 * Solaris 7 (and may be 8 as well) has a bug in pututline() that
 * interacts badly with prior invocation of getutline(): if
 * getutline() finds an entry, calling pututline() without first
 * calling setutent() will overwrite the record following the one that
 * was intended.
 *
 * Also, ut_exit in utmpx contains ut_e_termination and
 * ut_e_exit (otherwise it contains the expected e_termination and
 * e_exit) only if _XPG4_2 is defined and __EXTENSIONS__ is not, which
 * is not a compilation environment we're likely to encourage.  The
 * ut_exit field of utmp contains the expected fields.
 *
 * If _XPG4_2 is not defined or __EXTENSIONS__ is defined, the
 * functions getutmp(), getutmpx(), updwtmp(), and updwtmpx() are
 * available, as well as the undocumented functions makeutx() and
 * modutx().
 *
 * All the files utmp, utmpx, wtmp, and wtmpx exist.
 *
 * HP-UX 10.x:
 *
 * When init cleans up after processes it doesn't start, if the
 * process being cleaned up after allocated a pty, ut_line gets a
 * prefix of "pty/" for no readily apparent reason.  This causes
 * ut_line of logout entries in wtmp to not match that of their login
 * entries, confusing various utilities.
 *
 * Uses four-character unique IDs for /etc/inittab, which means that
 * programs not running out of init should use two-character ut_id
 * fields to avoid conflict.
 *
 * In utmpx, ut_exit contains __e_termination and __e_exit, while
 * ut_exit in utmp contains the expected fields.
 *
 * There is no wtmpx file, despite there being utmp and utmpx files.
 *
 * Irix 6.x:
 *
 * In utmpx, ut_exit contains __e_termination and __e_exit, which get
 * #define aliases e_termination and e_exit if _NO_XOPEN4 is true.
 * Curiously enough, utmp.h declares ut_exit to have __e_termination
 * and __e_exit as well, but does #define e_termination
 * __e_termination, etc. if another header (utmpx.h) hasn't already
 * declared struct __exit_status.  It seems that the default
 * compilation environment has the effect of making _NO_XOPEN4 true
 * though.
 *
 * If _NO_XOPEN4 is true, getutmp(), getutmpx(), updwtmp(), and
 * updwtmpx() are available, as well as the undocumented functions
 * makeutx() and modutx().
 *
 * All the files utmp, utmpx, wtmp, and wtmpx exist.
 *
 * Tru64 Unix 4.x:
 *
 * In utmpx, ut_exit contains ut_termination and ut_exit, while utmp
 * contains the expected fields.  The files utmp and wtmp seem to
 * exist, but not utmpx or wtmpx.
 *
 * AIX 4.3.x:
 *
 * The ut_exit field seems to exist in utmp, but not utmpx. The files
 * utmp and wtmp seem to exist, but not utmpx, or wtmpx.
 *
 * libpty Implementation Decisions:
 * --------------------------------
 *
 * We choose to use the pututxline() whenever possible, falling back
 * to pututline() and calling write() to write out struct utmp if
 * necessary.  The code to handle pututxline() and pututline() is
 * rather similar, since the structure members are quite similar, and
 * we make the assumption that it will never be necessary to call
 * both.  This allows us to avoid duplicating lots of code, by means
 * of some slightly demented macros.
 *
 * If neither pututxline() nor pututline() are available, we assume
 * BSD-style utmp files and behave accordingly, writing the structure
 * out to disk ourselves.
 *
 * On systems where updwtmpx() or updwtmp() are available, we use
 * those to update the wtmpx or wtmp file.  When they're not
 * available, we write the utmpx or utmp structure out to disk
 * ourselves, though sometimes conversion from utmpx to utmp format is
 * needed.
 */

#include <com_err.h>
#include "libpty.h"
#include "pty-int.h"

#if !defined(UTMP_FILE) && defined(_PATH_UTMP)
#define UTMP_FILE _PATH_UTMP
#endif

/* if it is *still* missing, assume SunOS */
#ifndef UTMP_FILE
#define	UTMP_FILE	"/etc/utmp"
#endif

/*
 * The following grossness exists to avoid duplicating lots of code
 * between the cases where we have an old-style sysV utmp and where we
 * have a modern (Unix98 or XPG4) utmpx.  See the above history rant
 * for further explanation.
 */
#if defined(HAVE_SETUTXENT) || defined(HAVE_SETUTENT)
#ifdef HAVE_SETUTXENT
#define PTY_STRUCT_UTMPX struct utmpx
#define PTY_SETUTXENT setutxent
#define PTY_GETUTXLINE getutxline
#define PTY_PUTUTXLINE pututxline
#define PTY_ENDUTXENT endutxent
#else
#define PTY_STRUCT_UTMPX struct utmp
#define PTY_SETUTXENT setutent
#define PTY_GETUTXLINE getutline
#define PTY_PUTUTXLINE pututline
#define PTY_ENDUTXENT endutent
#endif

static int better(const PTY_STRUCT_UTMPX *, const PTY_STRUCT_UTMPX *,
		  const PTY_STRUCT_UTMPX *);
static PTY_STRUCT_UTMPX *best_utxline(const PTY_STRUCT_UTMPX *);

/*
 * Utility function to determine whether A is a better match for
 * SEARCH than B.  Should only be called by best_utxline().
 */
static int
better(const PTY_STRUCT_UTMPX *search,
       const PTY_STRUCT_UTMPX *a, const PTY_STRUCT_UTMPX *b)
{
    if (strncmp(a->ut_id, b->ut_id, sizeof(b->ut_id))) {
	/* different UT_IDs; find the right one */
	if (a->ut_type == LOGIN_PROCESS) {
	    if (b->ut_type != LOGIN_PROCESS) {
		/* prefer LOGIN_PROCESS */
		return 1;
	    } else if (search->ut_pid == a->ut_pid
		       && a->ut_pid != b->ut_pid) {
		/*
		 * Prefer entry whose ut_pid matches that of SEARCH,
		 * if all else is the same.  Note that this will fail
		 * in the case of login.krb5 called from krlogind,
		 * etc., since the login.krb5 will have a different
		 * pid from its parent.  Consequently, we save this
		 * test for last, in order to catch the case of
		 * login.krb5 being called from getty.
		 */
		return 1;
	    }
	}
	return 0;
    } else {
	/*
	 * Bad juju.  We shouldn't get two entries with identical
	 * ut_id fields for the same value of ut_line.  pututxline()
	 * will probably pick the first entry, in spite of the strange
	 * state of utmpx, if we rewind with setutxent() first.
	 *
	 * For now, return 0, to force the earlier entry to be used.
	 */
	return 0;
    }
}

/*
 * This expects to be called with SEARCH pointing to a struct utmpx
 * with its ut_type equal to USER_PROCESS or DEAD_PROCESS, since if
 * we're making a LOGIN_PROCESS entry, we presumably don't care about
 * preserving existing state.  At the very least, the ut_pid, ut_line,
 * and ut_type fields must be filled in by the caller.
 */
static PTY_STRUCT_UTMPX *
best_utxline(const PTY_STRUCT_UTMPX *search)
{
    PTY_STRUCT_UTMPX utxtmp, *utxp;
    int i, best;

    i = best = 0;
    memset(&utxtmp, 0, sizeof(utxtmp));

    PTY_SETUTXENT();
    utxp = PTY_GETUTXLINE(search);
    if (utxp == NULL)
	return NULL;
    utxtmp = *utxp;

    for (;;) {
	memset(utxp, 0, sizeof(*utxp));
	utxp = PTY_GETUTXLINE(search);
	if (utxp == NULL)
	    break;
	i++;
	if (better(search, utxp, &utxtmp)) {
	    utxtmp = *utxp;
	    best = i;
	}
    }
    PTY_SETUTXENT();
    for (i = 0; i <= best; i++) {
	if (utxp != NULL)
	    memset(utxp, 0, sizeof(*utxp));
	utxp = PTY_GETUTXLINE(search);
    }
    PTY_ENDUTXENT();
    return utxp;
}

long
pty_update_utmp(int process_type, int pid, const char *username,
		    const char *line, const char *host, int flags)
{
    PTY_STRUCT_UTMPX utx, *utxtmp;
    const char *cp;
    size_t len;
    char utmp_id[5];

    /*
     * Zero things out in case there are fields we don't handle here.
     * They tend to be non-portable anyway.
     */
    memset(&utx, 0, sizeof(utx));
    utxtmp = NULL;
    cp = line;
    /*
     * XXX For some reason HP-UX init uses a prefix of "pty/" when
     * writing the process termination record to utmp and wtmp if the
     * line is a pty.  Not sure why.  Native HP-UX telnetd appears to
     * write its own process termination record without the "pty/"
     * prefix, and init or whatever doesn't clean up after it.
     */
    if (strncmp(cp, "/dev/", sizeof("/dev/") - 1) == 0)
	cp += sizeof("/dev/") - 1;
    strncpy(utx.ut_line, cp, sizeof(utx.ut_line));
    utx.ut_pid = pid;
    switch (process_type) {
    case PTY_LOGIN_PROCESS:
	utx.ut_type = LOGIN_PROCESS;
	break;
    case PTY_USER_PROCESS:
	utx.ut_type = USER_PROCESS;
	break;
    case PTY_DEAD_PROCESS:
	utx.ut_type = DEAD_PROCESS;
	break;
    default:
	return PTY_UPDATE_UTMP_PROCTYPE_INVALID;
    }
    /*
     * Get existing utmpx entry for LINE, if any, so we can copy some
     * stuff from it.  This is particularly important if we're running
     * out of getty, since getty will have written the entry for the
     * line with ut_type == LOGIN_PROCESS, and what it has recorded in
     * ut_id may not be what we come up with, since that's up to the
     * whim of the sysadmin who writes the inittab entry.
     *
     * We make the assumption that getty constructs ut_line the same
     * way that we do, which may be unwarranted.
     *
     * It seems that getty will find its ut_id by means of searching
     * for a utmpx entry of type INIT_PROCESS containing getty's pid
     * in ut_pid, though that is largely conjecture at the moment.
     * This should be irrelevant for this library, since none of its
     * callers should attempt to be a replacement for getty.
     */
    if (process_type != PTY_LOGIN_PROCESS)
	utxtmp = best_utxline(&utx);

#ifdef HAVE_SETUTXENT
    if (gettimeofday(&utx.ut_tv, NULL))
	return errno;
#else
    (void)time(&utx.ut_time);
#endif
    /*
     * On what system is there not ut_host?  Unix98 doesn't mandate
     * this field, but we have yet to see a system that supports utmpx
     * that doesn't have it.  For what it's worth, some ancient utmp
     * headers on svr4 systems imply that there's no ut_host in struct
     * utmp...
     */
#if (defined(HAVE_SETUTXENT) && defined(HAVE_STRUCT_UTMPX_UT_HOST))	\
	|| (!defined(HAVE_SETUTXENT) && defined(HAVE_STRUCT_UTMP_UT_HOST))
    if (host) {
	strncpy(utx.ut_host, host, sizeof(utx.ut_host));
	/* Unlike other things in utmpx, ut_host is nul-terminated? */
	utx.ut_host[sizeof(utx.ut_host) - 1] = '\0';
    } else
	utx.ut_host[0] = '\0';
#if (defined(HAVE_SETUTXENT) && defined(HAVE_STRUCT_UTMPX_UT_SYSLEN))	\
	|| (!defined (HAVE_SETUTXENT) && defined(HAVE_STRUCT_UTMP_UT_SYSLEN))
    if (host != NULL)
	utx.ut_syslen = strlen(utx.ut_host) + 1;
    else
	utx.ut_syslen = 0;
#endif
#endif

    /* XXX deal with ut_addr? */

    utx.ut_id[0] = '\0';

    if (utxtmp != NULL) {
	/*
	 * For entries not of type LOGIN_PROCESS, override some stuff
	 * with what was in the previous entry we found, if any.
	 */
	strncpy(utx.ut_id, utxtmp->ut_id, sizeof(utx.ut_id));
	utx.ut_pid = utxtmp->ut_pid;
    }

    if (utx.ut_id[0] == '\0') {
	len = strlen(line);
	if (len >= 2) {
	    cp = line + len - 1;
	    if (*(cp - 1) != '/')
		cp--;		/* last two characters, unless it's a / */
	} else
	    cp = line;
	/*
	 * HP-UX has mostly 4-character inittab ids, while most other
	 * sysV variants use only 2-charcter inittab ids, so to avoid
	 * conflicts, we pick 2-character ut_ids for our own use.  We
	 * may want to feature-test for this, but it would be somewhat
	 * of a pain, and would eit cross-compiling.
	 */
#ifdef __hpux
	strcpy(utmp_id, cp);
#else
	sprintf(utmp_id, "kl%s", cp);
#endif
	strncpy(utx.ut_id, utmp_id, sizeof(utx.ut_id));
    }
    strncpy(utx.ut_user, username, sizeof(utx.ut_user));

    PTY_SETUTXENT();
    PTY_PUTUTXLINE(&utx);
    PTY_ENDUTXENT();

    /* Don't record LOGIN_PROCESS entries. */
    if (process_type == PTY_LOGIN_PROCESS)
	return 0;

    if (username[0] == '\0'
	&& (flags & PTY_UTMP_USERNAME_VALID) && utxtmp != NULL)
	/* Use the ut_user from the entry we looked up, if any. */
	/* XXX Is this really necessary? */
	strncpy(utx.ut_user, utxtmp->ut_user, sizeof(utx.ut_user));

#ifdef HAVE_SETUTXENT
    return ptyint_update_wtmpx(&utx);
#else
    return ptyint_update_wtmp(&utx);
#endif
}

#else /* !(HAVE_SETUTXENT || HAVE_SETUTENT) */

long
pty_update_utmp(int process_type, int pid, const char *username,
		const char *line, const char *host, int flags)
{
    struct utmp ent, ut;
    int tty, lc, fd;
    struct stat statb;

    memset(&ent, 0, sizeof(ent));
#ifdef HAVE_STRUCT_UTMP_UT_HOST
    strncpy(ent.ut_host, host, sizeof(ent.ut_host));
#endif
    strncpy(ent.ut_name, username, sizeof(ent.ut_name));
    strncpy(ent.ut_line, line, sizeof(ent.ut_line));
    (void)time(&ent.ut_time);

    if (flags & PTY_TTYSLOT_USABLE) 
	tty = ttyslot();
    else {
	tty = -1;
	fd = open(UTMP_FILE, O_RDONLY);
	if (fd == -1)
	    return errno;
	for (lc = 0; ; lc++) {
	    if (lseek(fd, (off_t)(lc * sizeof(struct utmp)),
		      SEEK_SET))
		break;
	    if (read(fd, (char *) &ut, sizeof(struct utmp))
		!= sizeof(struct utmp))
		break;
	    if (strncmp(ut.ut_line, ent.ut_line, sizeof(ut.ut_line)) == 0) {
		tty = lc;
		break;
	    }
	}
	close(fd);
    }
    if (tty > 0) {
	fd = open(UTMP_FILE, OWRONLY);
	if (fd == -1)
	    return 0;
	if (fstat(fd, &statb)) {
	    close(fd);
	    return 0;
	}
	if (lseek(fd, (off_t)(tty * sizeof(struct utmp)), SEEK_SET)) {
	    close(fd);
	    return 0;
	}
	if (write(fd, (char *)&ent, sizeof(struct utmp))
	    != sizeof(struct utmp)) {
	    ftruncate(fd, statb.st_size);
	}
	close(fd);
    }
    /* Don't record LOGIN_PROCESS entries. */
    if (process_type == PTY_LOGIN_PROCESS)
	return 0;
    else
	return ptyint_update_wtmp(&ent);
}
#endif
