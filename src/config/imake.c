/*****************************************************************************\
 *                                                                           *
 *                                Porting Note                               *
 *                                                                           *
 * Add the value of BOOTSTRAPCFLAGS to the cpp_argv table so that it will be *
 * passed to the template file.                                              *
 *                                                                           *
\*****************************************************************************/



/*
 * 
 * Copyright 1985, 1986, 1987 by the Massachusetts Institute of Technology
 * 
 * Permission to use, copy, modify, and distribute this
 * software and its documentation for any purpose and without
 * fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright
 * notice and this permission notice appear in supporting
 * documentation, and that the name of M.I.T. not be used in
 * advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 * 
 * $XConsortium: imake.c,v 1.51 89/12/12 12:37:30 jim Exp $
 * $Locker$
 *
 * Author:
 *	Todd Brunhoff
 *	Tektronix, inc.
 *	While a guest engineer at Project Athena, MIT
 *
 * imake: the include-make program.
 *
 * Usage: imake [-Idir] [-Ddefine] [-T] [-f imakefile ] [-s] [-e] [-v] [make flags]
 *
 * Imake takes a template makefile (Imake.tmpl) and runs cpp on it
 * producing a temporary makefile in /tmp.  It then runs make on
 * this pre-processed makefile.
 * Options:
 *		-D	define.  Same as cpp -D argument.
 *		-I	Include directory.  Same as cpp -I argument.
 *		-T	template.  Designate a template other
 * 			than Imake.tmpl
 *		-s[F]	show.  Show the produced makefile on the standard
 *			output.  Make is not run is this case.  If a file
 *			argument is provided, the output is placed there.
 *              -e[F]   execute instead of show; optionally name Makefile F
 *		-v	verbose.  Show the make command line executed.
 *
 * Environment variables:
 *		
 *		IMAKEINCLUDE	Include directory to use in addition to "."
 *		IMAKECPP	Cpp to use instead of /lib/cpp
 *		IMAKEMAKE	make program to use other than what is
 *				found by searching the $PATH variable.
 * Other features:
 *	imake reads the entire cpp output into memory and then scans it
 *	for occurences of "@@".  If it encounters them, it replaces it with
 *	a newline.  It also trims any trailing white space on output lines
 *	(because make gets upset at them).  This helps when cpp expands
 *	multi-line macros but you want them to appear on multiple lines.
 *
 *	The macros MAKEFILE and MAKE are provided as macros
 *	to make.  MAKEFILE is set to imake's makefile (not the constructed,
 *	preprocessed one) and MAKE is set to argv[0], i.e. the name of
 *	the imake program.
 *
 * Theory of operation:
 *   1. Determine the name of the imakefile from the command line (-f)
 *	or from the content of the current directory (Imakefile or imakefile).
 *	Call this <imakefile>.  This gets added to the arguments for
 *	make as MAKEFILE=<imakefile>.
 *   2. Determine the name of the template from the command line (-T)
 *	or the default, Imake.tmpl.  Call this <template>
 *   3. Start up cpp an provide it with three lines of input:
 *		#define IMAKE_TEMPLATE		" <template> "
 *		#define INCLUDE_IMAKEFILE	< <imakefile> >
 *		#include IMAKE_TEMPLATE
 *	Note that the define for INCLUDE_IMAKEFILE is intended for
 *	use in the template file.  This implies that the imake is
 *	useless unless the template file contains at least the line
 *		#include INCLUDE_IMAKEFILE
 *   4. Gather the output from cpp, and clean it up, expanding @@ to
 *	newlines, stripping trailing white space, cpp control lines,
 *	and extra blank lines.  This cleaned output is placed in a
 *	temporary file.  Call this <makefile>.
 *   5. Start up make specifying <makefile> as its input.
 *
 * The design of the template makefile should therefore be:
 *	<set global macros like CFLAGS, etc.>
 *	<include machine dependent additions>
 *	#include INCLUDE_IMAKEFILE
 *	<add any global targets like 'clean' and long dependencies>
 */
#include	<stdio.h>
#include	<ctype.h>
#include	<sys/types.h>
#include	<sys/param.h>
#ifdef SYSV
#ifndef macII			/* mac will get the stuff out of file.h */
#include	<fcntl.h>
#endif
#else	/* !SYSV */
#include	<sys/wait.h>
#endif	/* !SYSV */
#include	<sys/file.h>
#include	<signal.h>
#include	<sys/stat.h>
#include "imakemdep.h"


#define	TRUE		1
#define	FALSE		0

#ifdef FIXUP_CPP_WHITESPACE
int	InRule = FALSE;
#endif

/*
 * Some versions of cpp reduce all tabs in macro expansion to a single
 * space.  In addition, the escaped newline may be replaced with a
 * space instead of being deleted.  Blech.
 */
#ifndef FIXUP_CPP_WHITESPACE
#define KludgeOutputLine(arg)
#define KludgeResetRule()
#endif

typedef	unsigned char	boolean;

#ifndef DEFAULT_CPP
#define DEFAULT_CPP "/lib/cpp"
#endif

char *cpp = DEFAULT_CPP;

char	*tmpMakefile    = "/tmp/Imf.XXXXXX";
char	*tmpImakefile    = "/tmp/IIf.XXXXXX";
char	*make_argv[ ARGUMENTS ] = { "make" };

int	make_argindex;
int	cpp_argindex;
char	*make = NULL;
char	*Imakefile = NULL;
char	*Makefile = "Makefile";
char	*Template = "Imake.tmpl";
char	*program;
char	*FindImakefile();
char	*ReadLine();
char	*CleanCppInput();
char	*strdup();

boolean	verbose = FALSE;
boolean	show = TRUE;
extern int	errno;
extern char	*Emalloc();
extern char	*realloc();
extern char	*getenv();
extern char	*mktemp();

main(argc, argv)
	int	argc;
	char	**argv;
{
	FILE	*tmpfd;
	char	makeMacro[ BUFSIZ ];
	char	makefileMacro[ BUFSIZ ];

	init();
	SetOpts(argc, argv);

	Imakefile = FindImakefile(Imakefile);
	if (Makefile)
		tmpMakefile = Makefile;
	else
		tmpMakefile = mktemp(strdup(tmpMakefile));
	AddMakeArg("-f");
	AddMakeArg( tmpMakefile );
	sprintf(makeMacro, "MAKE=%s", program);
	AddMakeArg( makeMacro );
	sprintf(makefileMacro, "MAKEFILE=%s", Imakefile);
	AddMakeArg( makefileMacro );

	if ((tmpfd = fopen(tmpMakefile, "w+")) == NULL)
		LogFatal("Cannot create temporary file %s.", tmpMakefile);

	cppit(Imakefile, Template, tmpfd, tmpMakefile);

	if (show) {
		if (Makefile == NULL)
			showit(tmpfd);
	} else
		makeit();
	wrapup();
	exit(0);
}

showit(fd)
	FILE	*fd;
{
	char	buf[ BUFSIZ ];
	int	red;

	fseek(fd, 0, 0);
	while ((red = fread(buf, 1, BUFSIZ, fd)) > 0)
		fwrite(buf, red, 1, stdout);
	if (red < 0)
		LogFatal("Cannot write stdout.", "");
}

wrapup()
{
	if (tmpMakefile != Makefile)
		unlink(tmpMakefile);
	unlink(tmpImakefile);
}

#if SIGNALRETURNSINT
int
#else
void
#endif
catch(sig)
	int	sig;
{
	errno = 0;
	LogFatalI("Signal %d.", sig);
}

/*
 * Initialize some variables.
 */
init()
{
	char	*p;

	make_argindex=0;
	while (make_argv[ make_argindex ] != NULL)
		make_argindex++;
	cpp_argindex = 0;
	while (cpp_argv[ cpp_argindex ] != NULL)
		cpp_argindex++;

	/*
	 * See if the standard include directory is different than
	 * the default.  Or if cpp is not the default.  Or if the make
	 * found by the PATH variable is not the default.
	 */
	if (p = getenv("IMAKEINCLUDE")) {
		if (*p != '-' || *(p+1) != 'I')
			LogFatal("Environment var IMAKEINCLUDE %s\n",
				"must begin with -I");
		AddCppArg(p);
		for (; *p; p++)
			if (*p == ' ') {
				*p++ = '\0';
				AddCppArg(p);
			}
	}
	if (p = getenv("IMAKECPP"))
		cpp = p;
	if (p = getenv("IMAKEMAKE"))
		make = p;

	if (signal(SIGINT, SIG_IGN) != SIG_IGN)
		signal(SIGINT, catch);
}

AddMakeArg(arg)
	char	*arg;
{
	errno = 0;
	if (make_argindex >= ARGUMENTS-1)
		LogFatal("Out of internal storage.", "");
	make_argv[ make_argindex++ ] = arg;
	make_argv[ make_argindex ] = NULL;
}

AddCppArg(arg)
	char	*arg;
{
	errno = 0;
	if (cpp_argindex >= ARGUMENTS-1)
		LogFatal("Out of internal storage.", "");
	cpp_argv[ cpp_argindex++ ] = arg;
	cpp_argv[ cpp_argindex ] = NULL;
}

SetOpts(argc, argv)
	int	argc;
	char	**argv;
{
	errno = 0;
	/*
	 * Now gather the arguments for make
	 */
	program = argv[0];
	for(argc--, argv++; argc; argc--, argv++) {
	    /*
	     * We intercept these flags.
	     */
	    if (argv[0][0] == '-') {
		if (argv[0][1] == 'D') {
		    AddCppArg(argv[0]);
		} else if (argv[0][1] == 'I') {
		    AddCppArg(argv[0]);
		} else if (argv[0][1] == 'f') {
		    if (argv[0][2])
			Imakefile = argv[0]+2;
		    else {
			argc--, argv++;
			if (! argc)
			    LogFatal("No description arg after -f flag\n", "");
			Imakefile = argv[0];
		    }
		} else if (argv[0][1] == 's') {
		    if (argv[0][2])
			Makefile = (argv[0][2] == '-') ? NULL : argv[0]+2;
		    else if (argc > 1 && argv[1][0] != '-') {
			argc--, argv++;
			Makefile = argv[0];
		    }
		    show = TRUE;
		} else if (argv[0][1] == 'e') {
		   Makefile = (argv[0][2] ? argv[0]+2 : NULL);
		   show = FALSE;
		} else if (argv[0][1] == 'T') {
		    if (argv[0][2])
			Template = argv[0]+2;
		    else {
			argc--, argv++;
			if (! argc)
			    LogFatal("No description arg after -T flag\n", "");
			Template = argv[0];
		    }
		} else if (argv[0][1] == 'v') {
		    verbose = TRUE;
		} else
		    AddMakeArg(argv[0]);
	    } else
		AddMakeArg(argv[0]);
	}
}

char *FindImakefile(Imakefile)
	char	*Imakefile;
{
	int	fd;

	if (Imakefile) {
		if ((fd = open(Imakefile, O_RDONLY)) < 0)
			LogFatal("Cannot open %s.", Imakefile);
	} else {
		if ((fd = open("Imakefile", O_RDONLY)) < 0)
			if ((fd = open("imakefile", O_RDONLY)) < 0)
				LogFatal("No description file.", "");
			else
				Imakefile = "imakefile";
		else
			Imakefile = "Imakefile";
	}
	close (fd);
	return(Imakefile);
}

LogFatalI(s, i)
	char *s;
	int i;
{
	/*NOSTRICT*/
	LogFatal(s, (char *)i);
}

LogFatal(x0,x1)
	char *x0, *x1;
{
	extern char	*sys_errlist[];
	static boolean	entered = FALSE;

	if (entered)
		return;
	entered = TRUE;

	fprintf(stderr, "%s: ", program);
	if (errno)
		fprintf(stderr, "%s: ", sys_errlist[ errno ]);
	fprintf(stderr, x0,x1);
	fprintf(stderr, "  Stop.\n");
	wrapup();
	exit(1);
}

showargs(argv)
	char	**argv;
{
	for (; *argv; argv++)
		fprintf(stderr, "%s ", *argv);
	fprintf(stderr, "\n");
}

cppit(Imakefile, template, outfd, outfname)
	char	*Imakefile;
	char	*template;
	FILE	*outfd;
	char	*outfname;
{
	FILE	*pipeFile;
	int	pid, pipefd[2];
#ifdef SYSV
	int	status;
#else	/* !SYSV */
	union wait	status;
#endif	/* !SYSV */
	char	*cleanedImakefile;

	/*
	 * Get a pipe.
	 */
	if (pipe(pipefd) < 0)
		LogFatal("Cannot make a pipe.", "");

	/*
	 * Fork and exec cpp
	 */
	pid = fork();
	if (pid < 0)
		LogFatal("Cannot fork.", "");
	if (pid) {	/* parent */
		close(pipefd[0]);
		cleanedImakefile = CleanCppInput(Imakefile);
		if ((pipeFile = fdopen(pipefd[1], "w")) == NULL)
			LogFatalI("Cannot fdopen fd %d for output.", pipefd[1]);
		fprintf(pipeFile, "#define IMAKE_TEMPLATE\t\"%s\"\n",
			template);
		fprintf(pipeFile, "#define INCLUDE_IMAKEFILE\t<%s>\n",
			cleanedImakefile);
		fprintf(pipeFile, "#include IMAKE_TEMPLATE\n");
		fclose(pipeFile);
		while (wait(&status) > 0) {
			errno = 0;
#ifdef SYSV
			if ((status >> 8) & 0xff)
				LogFatalI("Signal %d.", (status >> 8) & 0xff);
			if (status & 0xff)
				LogFatalI("Exit code %d.", status & 0xff);
#else	/* !SYSV */
			if (status.w_termsig)
				LogFatalI("Signal %d.", status.w_termsig);
			if (status.w_retcode)
				LogFatalI("Exit code %d.", status.w_retcode);
#endif	/* !SYSV */
		}
		CleanCppOutput(outfd, outfname);
	} else {	/* child... dup and exec cpp */
		if (verbose)
			showargs(cpp_argv);
		dup2(pipefd[0], 0);
		dup2(fileno(outfd), 1);
		close(pipefd[1]);
		execv(cpp, cpp_argv);
		LogFatal("Cannot exec %s.", cpp);
	}
}

makeit()
{
	int	pid;
#ifdef SYSV
	int	status;
#else	/* !SYSV */
	union wait	status;
#endif	/* !SYSV */

	/*
	 * Fork and exec make
	 */
	pid = fork();
	if (pid < 0)
		LogFatal("Cannot fork.", "");
	if (pid) {	/* parent... simply wait */
		while (wait(&status) > 0) {
			errno = 0;
#ifdef SYSV
			if ((status >> 8) & 0xff)
				LogFatalI("Signal %d.", (status >> 8) & 0xff);
			if (status & 0xff)
				LogFatalI("Exit code %d.", status & 0xff);
#else	/* !SYSV */
			if (status.w_termsig)
				LogFatalI("Signal %d.", status.w_termsig);
			if (status.w_retcode)
				LogFatalI("Exit code %d.", status.w_retcode);
#endif	/* !SYSV */
		}
	} else {	/* child... dup and exec cpp */
		if (verbose)
			showargs(make_argv);
		if (make)
			execv(make, make_argv);
		else
			execvp("make", make_argv);
		LogFatal("Cannot exec %s.", cpp);
	}
}

char *CleanCppInput(Imakefile)
	char	*Imakefile;
{
	FILE	*outFile = NULL;
	int	infd;
	char	*buf,		/* buffer for file content */
		*pbuf,		/* walking pointer to buf */
		*punwritten,	/* pointer to unwritten portion of buf */
		*cleanedImakefile = Imakefile,	/* return value */
		*ptoken,	/* pointer to # token */
		*pend,		/* pointer to end of # token */
		savec;		/* temporary character holder */
	struct stat	st;

	/*
	 * grab the entire file.
	 */
	if ((infd = open(Imakefile, O_RDONLY)) < 0)
		LogFatal("Cannot open %s for input.", Imakefile);
	fstat(infd, &st);
	buf = Emalloc(st.st_size+1);
	if (read(infd, buf, st.st_size) != st.st_size)
		LogFatal("Cannot read all of %s:", Imakefile);
	close(infd);
	buf[ st.st_size ] = '\0';

	punwritten = pbuf = buf;
	while (*pbuf) {
	    /* pad make comments for cpp */
	    if (*pbuf == '#' && (pbuf == buf || pbuf[-1] == '\n')) {

		ptoken = pbuf+1;
		while (*ptoken == ' ' || *ptoken == '\t')
			ptoken++;
		pend = ptoken;
		while (*pend && *pend != ' ' && *pend != '\t' && *pend != '\n')
			pend++;
		savec = *pend;
		*pend = '\0';
		if (strcmp(ptoken, "include")
		 && strcmp(ptoken, "define")
		 && strcmp(ptoken, "undef")
		 && strcmp(ptoken, "ifdef")
		 && strcmp(ptoken, "ifndef")
		 && strcmp(ptoken, "else")
		 && strcmp(ptoken, "endif")
		 && strcmp(ptoken, "if")) {
		    if (outFile == NULL) {
			tmpImakefile = mktemp(strdup(tmpImakefile));
			cleanedImakefile = tmpImakefile;
			outFile = fopen(tmpImakefile, "w");
			if (outFile == NULL)
			    LogFatal("Cannot open %s for write.\n",
				tmpImakefile);
		    }
		    fwrite(punwritten, sizeof(char), pbuf-punwritten, outFile);
		    fputs("/**/", outFile);
		    punwritten = pbuf;
		}
		*pend = savec;
	    }
	    pbuf++;
	}
	if (outFile) {
	    fwrite(punwritten, sizeof(char), pbuf-punwritten, outFile);
	    fclose(outFile); /* also closes the pipe */
	}

	return(cleanedImakefile);
}

CleanCppOutput(tmpfd, tmpfname)
	FILE	*tmpfd;
	char	*tmpfname;
{
	char	*input;
	int	blankline = 0;

	while(input = ReadLine(tmpfd, tmpfname)) {
		if (isempty(input)) {
			if (blankline++)
				continue;
			KludgeResetRule();
		} else {
			blankline = 0;
			KludgeOutputLine(&input);
			fputs(input, tmpfd);
		}
		putc('\n', tmpfd);
	}
	fflush(tmpfd);
#ifdef NFS_STDOUT_BUG
	/*
	 * On some systems, NFS seems to leave a large number of nulls at
	 * the end of the file.  Ralph Swick says that this kludge makes the
	 * problem go away.
	 */
	ftruncate (fileno(tmpfd), (off_t)ftell(tmpfd));
#endif
}

/*
 * Determine of a line has nothing in it.  As a side effect, we trim white
 * space from the end of the line.  Cpp magic cookies are also thrown away.
 */
isempty(line)
	char	*line;
{
	char	*pend;

	/*
	 * Check for lines of the form
	 *	# n "...
	 * or
	 *	# line n "...
	 */
	if (*line == '#') {
		pend = line+1;
		if (*pend == ' ')
			pend++;
		if (strncmp(pend, "line ", 5) == 0)
			pend += 5;
		if (isdigit(*pend)) {
			while (isdigit(*pend))
				pend++;
			if (*pend++ == ' ' && *pend == '"')
				return(TRUE);
		}
	}

	/*
	 * Find the end of the line and then walk back.
	 */
	for (pend=line; *pend; pend++) ;

	pend--;
	while (pend >= line && (*pend == ' ' || *pend == '\t'))
		pend--;
	*++pend = '\0';
	return (*line == '\0');
}

/*ARGSUSED*/
char *ReadLine(tmpfd, tmpfname)
	FILE	*tmpfd;
	char	*tmpfname;
{
	static boolean	initialized = FALSE;
	static char	*buf, *pline, *end;
	char	*p1, *p2;

	if (! initialized) {
		int	total_red;
		struct stat	st;

		/*
		 * Slurp it all up.
		 */
		fseek(tmpfd, 0, 0);
		fstat(fileno(tmpfd), &st);
		pline = buf = Emalloc(st.st_size+1);
		total_red = read(fileno(tmpfd), buf, st.st_size);
		if (total_red != st.st_size)
			LogFatal("cannot read %s\n", tmpMakefile);
		end = buf + st.st_size;
		*end = '\0';
		lseek(fileno(tmpfd), 0, 0);
#ifdef SYSV
		freopen(tmpfname, "w+", tmpfd);
#else	/* !SYSV */
		ftruncate(fileno(tmpfd), 0);
#endif	/* !SYSV */
		initialized = TRUE;
	    fprintf (tmpfd, "# Makefile generated by imake - do not edit!\n");
	    fprintf (tmpfd, "# %s\n",
		"$XConsortium: imake.c,v 1.51 89/12/12 12:37:30 jim Exp $");

#ifdef FIXUP_CPP_WHITESPACE
	    {
		static char *cpp_warning[] = {
"#",
"# The cpp used on this machine replaces all newlines and multiple tabs and",
"# spaces in a macro expansion with a single space.  Imake tries to compensate",
"# for this, but is not always successful.",
"#",
NULL };
		char **cpp;

		for (cpp = cpp_warning; *cpp; cpp++) {
		    fprintf (tmpfd, "%s\n", *cpp);
		}
	    }
#endif /* FIXUP_CPP_WHITESPACE */
	}

	for (p1 = pline; p1 < end; p1++) {
		if (*p1 == '@' && *(p1+1) == '@') { /* soft EOL */
			*p1++ = '\0';
			p1++; /* skip over second @ */
			break;
		}
		else if (*p1 == '\n') { /* real EOL */
			*p1++ = '\0';
			break;
		}
	}

	/*
	 * return NULL at the end of the file.
	 */
	p2 = (pline == p1 ? NULL : pline);
	pline = p1;
	return(p2);
}

writetmpfile(fd, buf, cnt)
	FILE	*fd;
	int	cnt;
	char	*buf;
{
	errno = 0;
	if (fwrite(buf, cnt, 1, fd) != 1)
		LogFatal("Cannot write to %s.", tmpMakefile);
}

char *Emalloc(size)
	int	size;
{
	char	*p, *malloc();

	if ((p = malloc(size)) == NULL)
		LogFatalI("Cannot allocate %d bytes\n", size);
	return(p);
}

#ifdef FIXUP_CPP_WHITESPACE
KludgeOutputLine(pline)
	char	**pline;
{
	char	*p = *pline;

	switch (*p) {
	    case '#':	/*Comment - ignore*/
		break;
	    case '\t':	/*Already tabbed - ignore it*/
	    	break;
	    case ' ':	/*May need a tab*/
	    default:
		for (; *p; p++) if (p[0] == ':' && 
				    p > *pline && p[-1] != '\\') {
		    if (**pline == ' ')
			(*pline)++;
		    InRule = TRUE;
		    break;
		}
		if (InRule && **pline == ' ')
		    **pline = '\t';
		break;
	}
}

KludgeResetRule()
{
	InRule = FALSE;
}
#endif /* FIXUP_CPP_WHITESPACE */

char *strdup(cp)
	register char *cp;
{
	register char *new = Emalloc(strlen(cp) + 1);

	strcpy(new, cp);
	return new;
}
