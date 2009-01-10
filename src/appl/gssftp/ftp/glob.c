/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef lint
static char sccsid[] = "@(#)glob.c	5.9 (Berkeley) 2/25/91";
#endif /* not lint */

/*
 * C-shell glob for random programs.
 */

#include <sys/stat.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifndef _WIN32
#include <sys/param.h>
#include <dirent.h>
#include <pwd.h>
#endif

#ifdef POSIX
#include <limits.h>
#endif

#include <k5-platform.h>

#include "ftp_var.h"

#ifdef ARG_MAX
#undef NCARGS
#define NCARGS ARG_MAX
#endif

#ifndef NCARGS
#define NCARGS 4096
#endif

#define	QUOTE 0200
#define	TRIM 0177
#define	eq(a,b)		(strcmp(a, b)==0)
#define	GAVSIZ		(NCARGS/6)
#define	isdir(d)	((d.st_mode & S_IFMT) == S_IFDIR)

static	char **gargv;		/* Pointer to the (stack) arglist */
static	int gargc;		/* Number args in gargv */
static	int gnleft;
static	short gflag;
char	**ftpglob();
char	*globerr;
char	*home;
static	char *strspl (char *, char *), *strend (char *);
char	**copyblk (char **);

static void acollect (char *), addpath (int), 
  collect (char *), expand (char *), 
  Gcat (char *, char *);
static void ginit (char **), matchdir (char *),
  rscan (char **, int (*f)()), sort (void);
static int amatch (char *, char *), 
  execbrc (char *, char *), match (char *, char *);
static int digit (int), letter (int),
  any (int, char *);
#ifndef _WIN32
static int gethdir (char *);
#endif
static int tglob (int );

static	int globcnt;

char	*globchars = "`{[*?";

static	char *gpath, *gpathp, *lastgpathp;
static	int globbed;
static	char *entp;
static	char **sortbas;

char **
ftpglob(v)
	register char *v;
{
	char agpath[FTP_BUFSIZ];
	char *agargv[GAVSIZ];
	char *vv[2];
	vv[0] = v;
	vv[1] = 0;
	gflag = 0;
	rscan(vv, tglob);
	if (gflag == 0) {
	  /* Caller will always free the contents, so make a copy.  */
	  size_t len = strlen (v) + 1;
	  vv[0] = malloc (len);
	  if (vv[0] == 0) {
	    globerr = "Can't allocate memory";
	    return 0;
	  }
	  memcpy (vv[0], v, len);
	  return (copyblk(vv));
	}

	globerr = 0;
	gpath = agpath; gpathp = gpath; *gpathp = 0;
	lastgpathp = &gpath[sizeof(agpath) - 1];
	ginit(agargv); globcnt = 0;
	collect(v);
	if (globcnt == 0 && (gflag&1)) {
		blkfree(gargv), gargv = 0;
		return (0);
	} else
		return (gargv = copyblk(gargv));
}

static void
ginit(agargv)
	char **agargv;
{

	agargv[0] = 0; gargv = agargv; sortbas = agargv; gargc = 0;
	gnleft = NCARGS - 4;
}

static void
collect(as)
	register char *as;
{
	if (eq(as, "{") || eq(as, "{}")) {
		Gcat(as, "");
		sort();
	} else
		acollect(as);
}

static void
acollect(as)
	register char *as;
{
	register int ogargc = gargc;

	gpathp = gpath; *gpathp = 0; globbed = 0;
	expand(as);
	if (gargc != ogargc)
		sort();
}

static void
sort()
{
	register char **p1, **p2, *c;
	char **Gvp = &gargv[gargc];

	p1 = sortbas;
	while (p1 < Gvp-1) {
		p2 = p1;
		while (++p2 < Gvp)
			if (strcmp(*p1, *p2) > 0)
				c = *p1, *p1 = *p2, *p2 = c;
		p1++;
	}
	sortbas = Gvp;
}

static void
expand(as)
	char *as;
{
	register char *cs;
	register char *sgpathp, *oldcs;
	struct stat stb;

	sgpathp = gpathp;
	cs = as;
#ifndef _WIN32
	if (*cs == '~' && gpathp == gpath) {
		addpath('~');
		for (cs++; letter(*cs) || digit(*cs) || *cs == '-';)
			addpath(*cs++);
		if (!*cs || *cs == '/') {
			if (gpathp != gpath + 1) {
				*gpathp = 0;
				if (gethdir(gpath + 1))
					globerr = "Unknown user name after ~";
				(void) memmove(gpath, gpath + 1,
					       strlen(gpath));
			} else
				(void) strncpy(gpath, home, FTP_BUFSIZ - 1);
			gpath[FTP_BUFSIZ - 1] = '\0';
			gpathp = strend(gpath);
		}
	}
#endif
	while (!any(*cs, globchars)) {
		if (*cs == 0) {
			if (!globbed)
				Gcat(gpath, "");
			else if (stat(gpath, &stb) >= 0) {
				Gcat(gpath, "");
				globcnt++;
			}
			goto endit;
		}
		addpath(*cs++);
	}
	oldcs = cs;
	while (cs > as && *cs != '/')
		cs--, gpathp--;
	if (*cs == '/')
		cs++, gpathp++;
	*gpathp = 0;
	if (*oldcs == '{') {
		(void) execbrc(cs, ((char *)0));
		return;
	}
	matchdir(cs);
endit:
	gpathp = sgpathp;
	*gpathp = 0;
}

#ifdef _WIN32

static void
matchdir(pattern)
	char *pattern;
{
	HANDLE hFile = INVALID_HANDLE_VALUE;
	WIN32_FIND_DATA file_data;
	char *base = *gpath ? gpath : ".";
	char *buffer = 0;

	if (asprintf(&buffer, "%s\\*", base) < 0) return;
	hFile = FindFirstFile(buffer, &file_data);
	if (hFile == INVALID_HANDLE_VALUE) {
		if (!globbed)
			globerr = "Bad directory components";
		return;
	}
	do {
		if (match(file_data.cFileName, pattern)) {
			Gcat(gpath, file_data.cFileName);
			globcnt++;
		}
	} while (FindNextFile(hFile, &file_data));
	FindClose(hFile);
}

#else /* !_WIN32 */

static void
matchdir(pattern)
	char *pattern;
{
#if 0
	struct stat stb;
#endif
	register struct dirent *dp;
	DIR *dirp;

	dirp = opendir(*gpath?gpath:".");
	if (dirp == NULL) {
		if (globbed)
			return;
		goto patherr2;
	}
	/* This fails on systems where you can't inspect the contents of
	   the DIR structure.  If there are systems whose opendir does
	   not check for a directory, then use stat, not fstat. */
#if 0
	if (fstat(dirp->dd_fd, &stb) < 0)
		goto patherr1;
	if (!isdir(stb)) {
		errno = ENOTDIR;
		goto patherr1;
	}
#endif
	while ((dp = readdir(dirp)) != NULL) {
		if (dp->d_ino == 0)
			continue;
		if (match(dp->d_name, pattern)) {
			Gcat(gpath, dp->d_name);
			globcnt++;
		}
	}
	closedir(dirp);
	return;

#if 0
patherr1:
#endif
	closedir(dirp);
patherr2:
	globerr = "Bad directory components";
}

#endif /* !_WIN32 */

static int
execbrc(p, s)
	char *p, *s;
{
	char restbuf[FTP_BUFSIZ + 2];
	register char *pe, *pm, *pl;
	int brclev = 0;
	char *lm, savec, *sgpathp;

	for (lm = restbuf; *p != '{'; *lm++ = *p++)
		continue;
	/* pe starts pointing to one past the first '{'. */
	for (pe = ++p; *pe; pe++)
	switch (*pe) {

	case '{':
		brclev++;
		continue;

	case '}':
		if (brclev == 0)
			goto pend;
		brclev--;
		continue;

	case '[':
		for (pe++; *pe && *pe != ']'; pe++)
			continue;
		if (!*pe)
			pe--;
		continue;
	}
pend:
	brclev = 0;
	for (pl = pm = p; pm <= pe; pm++)
	switch (*pm & (QUOTE|TRIM)) {

	case '{':
		brclev++;
		continue;

	case '}':
		if (brclev) {	/* brclev = 0 is outermost brace set */
			brclev--;
			continue;
		}
		goto doit;

	case ','|QUOTE:
	case ',':
		if (brclev)
			continue;
doit:
		savec = *pm;
		*pm = 0;
		(void) strncpy(lm, pl, sizeof(restbuf) - 1 - (lm - restbuf));
		restbuf[sizeof(restbuf) - 1] = '\0';
		if (*pe) {
			(void) strncat(restbuf, pe + 1,
				       sizeof(restbuf) - 1 - strlen(restbuf));
		}
		*pm = savec;
		if (s == 0) {
			sgpathp = gpathp;
			expand(restbuf);
			gpathp = sgpathp;
			*gpathp = 0;
		} else if (amatch(s, restbuf))
			return (1);
		sort();
		pl = pm + 1;
		if (brclev)
			return (0);
		continue;

	case '[':
		for (pm++; *pm && *pm != ']'; pm++)
			continue;
		if (!*pm)
			pm--;
		continue;
	}
	if (brclev)
		goto doit;
	return (0);
}

static int
match(s, p)
	char *s, *p;
{
	register int c;
	register char *sentp;
	char sglobbed = globbed;

	if (*s == '.' && *p != '.')
		return (0);
	sentp = entp;
	entp = s;
	c = amatch(s, p);
	entp = sentp;
	globbed = sglobbed;
	return (c);
}

static int
amatch(s, p)
	register char *s, *p;
{
	register int scc;
	int ok, lc;
	char *sgpathp;
	struct stat stb;
	int c, cc;

	globbed = 1;
	for (;;) {
		scc = *s++ & TRIM;
		switch (c = *p++) {

		case '{':
			return (execbrc(p - 1, s - 1));

		case '[':
			ok = 0;
			lc = 077777;
			while ((cc = *p++)) {
				if (cc == ']') {
					if (ok)
						break;
					return (0);
				}
				if (cc == '-') {
					if (lc <= scc && scc <= *p++)
						ok++;
				} else
					if (scc == (lc = cc))
						ok++;
			}
			if (cc == 0) {
				if (ok)
					p--;
				else
					return 0;
			}
			continue;

		case '*':
			/* Multiple stars are equivalent to one.
			   Don't chew up cpu time with O(n**2)
			   recursion if a long string of them is
			   given.  */
			while (*p == '*')
				p++;
			if (!*p)
				return (1);
			if (*p == '/') {
				p++;
				goto slash;
			}
			s--;
			do {
				if (amatch(s, p))
					return (1);
			} while (*s++);
			return (0);

		case 0:
			return (scc == 0);

		default:
			if (c != scc)
				return (0);
			continue;

		case '?':
			if (scc == 0)
				return (0);
			continue;

		case '/':
			if (scc)
				return (0);
slash:
			s = entp;
			sgpathp = gpathp;
			while (*s)
				addpath(*s++);
			addpath('/');
			if (stat(gpath, &stb) == 0 && isdir(stb)) {
				if (*p == 0) {
					Gcat(gpath, "");
					globcnt++;
				} else
					expand(p);
			}
			gpathp = sgpathp;
			*gpathp = 0;
			return (0);
		}
	}
}

static int
Gmatch(s, p)
	register char *s, *p;
{
	register int scc;
	int ok, lc;
	int c, cc;

	for (;;) {
		scc = *s++ & TRIM;
		switch (c = *p++) {

		case '[':
			ok = 0;
			lc = 077777;
			while ((cc = *p++)) {
				if (cc == ']') {
					if (ok)
						break;
					return (0);
				}
				if (cc == '-') {
					if (lc <= scc && scc <= *p++)
						ok++;
				} else
					if (scc == (lc = cc))
						ok++;
			}
			if (cc == 0) {
				if (ok)
					p--;
				else
					return 0;
			}
			continue;

		case '*':
			if (!*p)
				return (1);
			for (s--; *s; s++)
				if (Gmatch(s, p))
					return (1);
			return (0);

		case 0:
			return (scc == 0);

		default:
			if ((c & TRIM) != scc)
				return (0);
			continue;

		case '?':
			if (scc == 0)
				return (0);
			continue;

		}
	}
}

static void
Gcat(s1, s2)
	register char *s1, *s2;
{
	register int len = strlen(s1) + strlen(s2) + 1;

	if (len >= gnleft || gargc >= GAVSIZ - 1)
		globerr = "Arguments too long";
	else {
		gargc++;
		gnleft -= len;
		gargv[gargc] = 0;
		gargv[gargc - 1] = strspl(s1, s2);
	}
}

static void
addpath(c)
	int c;
{

	if (gpathp >= lastgpathp)
		globerr = "Pathname too long";
	else {
		*gpathp++ = c & 0xff;
		*gpathp = 0;
	}
}

static void
rscan(t, f)
	register char **t;
	int (*f)();
{
	register char *p, c;

	while ((p = *t++)) {
		if (f == tglob) {
			if (*p == '~')
				gflag |= 2;
			else if (eq(p, "{") || eq(p, "{}"))
				continue;
		}
		while ((c = *p++))
			(*f)(c);
	}
}
/*
static
scan(t, f)
	register char **t;
	int (*f)();
{
	register char *p, c;

	while (p = *t++)
		while (c = *p)
			*p++ = (*f)(c);
} */

static int
tglob(c)
	register int c;
{

	if (any(c, globchars))
		gflag |= c == '{' ? 2 : 1;
	return (c);
}
/*
static
trim(c)
	char c;
{

	return (c & TRIM);
} */


static int
letter(c)
	register int c;
{

	return ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_');
}

static int
digit(c)
	register int c;
{

	return (c >= '0' && c <= '9');
}

static int any(c, s)
	register int c;
	register char *s;
{

	while (*s)
		if (*s++ == c)
			return(1);
	return(0);
}
static int blklen(av)
	register char **av;
{
	register int i = 0;

	while (*av++)
		i++;
	return (i);
}

static char **
blkcpy(oav, bv)
	char **oav;
	register char **bv;
{
	register char **av = oav;

	while ((*av++ = *bv++))
		continue;
	return (oav);
}

void blkfree(av0)
	char **av0;
{
	register char **av = av0;

	while (*av)
		free(*av++);
}

static
char *
strspl(cp, dp)
	register char *cp, *dp;
{
	char *ep;

	if (asprintf(&ep, "%s%s", cp, dp) < 0)
		fatal("Out of memory");
	return (ep);
}

char **
copyblk(v)
	register char **v;
{
	register char **nv = (char **)malloc((unsigned)((blklen(v) + 1) *
						sizeof(char **)));
	if (nv == (char **)0)
		fatal("Out of memory");

	return (blkcpy(nv, v));
}

static
char *
strend(cp)
	register char *cp;
{

	while (*cp)
		cp++;
	return (cp);
}

#ifndef _WIN32
/*
 * Extract a home directory from the password file
 * The argument points to a buffer where the name of the
 * user whose home directory is sought is currently.
 * We write the home directory of the user back there.
 */
static int gethdir(mhome)
	char *mhome;
{
	register struct passwd *pp = getpwnam(mhome);
	size_t bufsize = lastgpathp - mhome;

	if (!pp)
		return (1);
	if (strlcpy(mhome, pp->pw_dir, bufsize) >= bufsize)
		return (1);
	return (0);
}
#endif
