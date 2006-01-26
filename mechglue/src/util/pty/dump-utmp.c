/*
 * Copyright 2001 by the Massachusetts Institute of Technology.
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
 *
 * dump-utmp.c: dump utmp and utmpx format files for debugging purposes.
 */

#include <sys/types.h>
#include <sys/file.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#ifndef UTMPX
#ifdef HAVE_UTMPX_H
#define UTMPX
#endif
#endif

#if defined(HAVE_UTMPNAME) || defined(HAVE_UTMPXNAME)
#define UTN			/* we can set utmp or utmpx for getut*() */
#endif

#ifdef UTMPX
#include <utmpx.h>
void print_utx(int, const struct utmpx *);
#endif
#include <utmp.h>

void print_ut(int, const struct utmp *);

void usage(const char *);

#if defined (HAVE_STRUCT_UTMP_UT_TYPE) || defined (UTMPX)
char *ut_typename(int);

char *
ut_typename(int t) {
    switch (t) {
#define S(N) case N : return #N
#define S2(N,N2) case N : return #N2
	S(EMPTY);
	S(RUN_LVL);
	S(BOOT_TIME);
	S(OLD_TIME);
	S(NEW_TIME);
	S2(INIT_PROCESS,INIT);
	S2(LOGIN_PROCESS,LOGIN);
	S2(USER_PROCESS,USER);
	S2(DEAD_PROCESS,DEAD);
	S(ACCOUNTING);
    default: return "??";
    }
}
#endif

#define S2D(x) (sizeof(x) * 2.4 + 1.5)

void
print_ut(int all, const struct utmp *u)
{
    int lu, ll;
#ifdef HAVE_STRUCT_UTMP_UT_ID
    int lid;
#endif
#ifdef HAVE_STRUCT_UTMP_UT_PID
    int lpid;
#endif
#ifdef PTY_UTMP_E_EXIT
    int let, lee;
#endif

#ifdef HAVE_STRUCT_UTMP_UT_TYPE
    if (!all && ((u->ut_type == EMPTY) || (u->ut_type == DEAD_PROCESS)))
	return;
#endif

    lu = sizeof(u->ut_name);
    ll = sizeof(u->ut_line);
    printf("%-*.*s:", lu, lu, u->ut_name);
    printf("%-*.*s:", ll, ll, u->ut_line);
#ifdef HAVE_STRUCT_UTMP_UT_ID
    lid = sizeof(u->ut_id);
    printf("%-*.*s:", lid, lid, u->ut_id);
#endif
#ifdef HAVE_STRUCT_UTMP_UT_PID
    lpid = S2D(u->ut_pid);
    printf("%*ld", lpid, (long)u->ut_pid);
#endif
#ifdef PTY_UTMP_E_EXIT
    let = S2D(u->ut_exit.PTY_UTMP_E_TERMINATION);
    lee = S2D(u->ut_exit.PTY_UTMP_E_EXIT);
    printf("(%*ld,", let, (long)u->ut_exit.PTY_UTMP_E_TERMINATION);
    printf("%*ld)", lee, (long)u->ut_exit.PTY_UTMP_E_EXIT);
#endif
#ifdef HAVE_STRUCT_UTMP_UT_TYPE
    printf(" %-9s", ut_typename(u->ut_type));
#endif
    printf(" %s", ctime(&u->ut_time) + 4);
#ifdef HAVE_STRUCT_UTMP_UT_HOST
    if (u->ut_host[0])
	printf(" %.*s\n", (int) sizeof(u->ut_host), u->ut_host);
#endif

    return;
}

#ifdef UTMPX
void
print_utx(int all, const struct utmpx *u)
{
    int lu, ll, lid, lpid;
#ifdef PTY_UTMPX_E_EXIT
    int let, lee;
#endif

    if (!all && ((u->ut_type == EMPTY) || (u->ut_type == DEAD_PROCESS)))
	return;

    lu = sizeof(u->ut_user);
    ll = sizeof(u->ut_line);
    lid = sizeof(u->ut_id);
    printf("%-*.*s:", lu, lu, u->ut_user);
    printf("%-*.*s:", ll, ll, u->ut_line);
    printf("%-*.*s", lid, lid, u->ut_id);
    if (lu + ll + lid >= 60)
	printf("\n");
    else
	printf(":");
    lpid = S2D(u->ut_pid);
    printf("%*ld", lpid, (long)u->ut_pid);
#ifdef PTY_UTMPX_E_EXIT
    let = S2D(u->ut_exit.PTY_UTMPX_E_TERMINATION);
    lee = S2D(u->ut_exit.PTY_UTMPX_E_EXIT);
    printf("(%*ld,", let, (long)u->ut_exit.PTY_UTMPX_E_TERMINATION);
    printf("%*ld)", lee, (long)u->ut_exit.PTY_UTMPX_E_EXIT);
#endif
    printf(" %-9s", ut_typename(u->ut_type));
    printf(" %s", ctime(&u->ut_tv.tv_sec) + 4);
#ifdef HAVE_STRUCT_UTMPX_UT_HOST
    if (u->ut_host[0])
	printf(" %s\n", u->ut_host);
#endif

    return;
}
#endif

#ifdef UTMPX
#define OPTX "x"
#else
#define OPTX
#endif
#ifdef UTN
#define OPTG "g"
#else
#define OPTG
#endif
#define OPTS "a" OPTX OPTG

void
usage(const char *prog)
{
    fprintf(stderr, "usage: %s [-" OPTS "] file\n", prog);
    exit(1);
}

int
main(int argc, char **argv)
{
    int c;
    int all, is_utmpx, do_getut;
    int f;
    char *fn;
    size_t recsize;
    size_t nread;
    union {
	struct utmp ut;
#ifdef UTMPX
	struct utmpx utx;
#endif
    } u;

    all = is_utmpx = do_getut = 0;
    recsize = sizeof(struct utmp);

    while ((c = getopt(argc, argv, OPTS)) != EOF) {
	switch (c) {
	case 'a':
	    all = 1;
	    break;
#ifdef UTMPX
	case 'x':
	    is_utmpx = 1;
	    recsize = sizeof(struct utmpx);
	    break;
#endif
#ifdef UTN
	case 'g':
	    do_getut = 1;
	    break;
#endif
	default:
	    usage(argv[0]);
	}
    }
    if (argc <= optind)
	usage(argv[0]);
    fn = argv[optind];
    if (!do_getut) {
	f = open(fn, O_RDONLY);
	if (f == -1) {
	    perror(fn);
	    exit(1);
	}
	while ((nread = read(f, &u, recsize)) > 0) {
	    if (nread < recsize) {
		fprintf(stderr, "short read");
		close(f);
		exit(1);
	    }
	    if (is_utmpx) {
#ifdef UTMPX
		print_utx(all, &u.utx);
#else
		abort();
#endif
	    } else {
		print_ut(all, &u.ut);
	    }
	}
	if (nread == -1) {
	    perror("read");
	    exit(1);
	}
	close(f);
    } else {
	if (is_utmpx) {
#ifdef UTMPX
#ifdef HAVE_UTMPXNAME
	    struct utmpx *utxp;
	    utmpxname(fn);
	    setutxent();
	    while ((utxp = getutxent()) != NULL)
		print_utx(all, utxp);
#else
	    fprintf(stderr, "no utmpxname(); can't use getutxent()\n");
	    exit(1);
#endif
#else
	    abort();
#endif
	} else {
#ifdef HAVE_UTMPNAME
	    struct utmp *utp;
	    utmpname(fn);
	    setutxent();
	    while ((utp = getutent()) != NULL)
		print_ut(all, utp);
#else
	    fprintf(stderr, "no utmpname(); can't use getutent()\n");
	    exit(1);
#endif
	}
    }
    exit(0);    
}
