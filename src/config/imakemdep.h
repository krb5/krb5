/*
 * $XConsortium: imakemdep.h,v 1.10 89/12/18 16:56:38 jim Exp $
 * 
 * This file contains machine-dependent constants for the imake utility.  When
 * porting imake, read each of the steps below and add in any necessary
 * definitions.  Do *not* edit ccimake.c or imake.c!
 */

#ifdef CCIMAKE
/*
 * Step 1:  imake_ccflags
 *     Define any special flags that will be needed to get imake.c to compile.
 *     These will be passed to the compile along with the contents of the
 *     make variable BOOTSTRAPCFLAGS.
 */
#ifdef hpux
#define imake_ccflags "-Wc,-Nd4000,-Ns3000 -DSYSV"
#endif

#ifdef macII
#define imake_ccflags "-DSYSV"
#endif

#ifdef stellar
#define imake_ccflags "-DSYSV"
#endif

#ifdef att
#define imake_ccflags "-DSYSV -DUSG"
#endif

#ifdef CRAY
#define imake_ccflags "-DSYSV -DUSG"
#endif

#ifdef aix
#define imake_ccflags "-Daix -DSYSV"
#endif

#ifdef umips
#ifdef SYSTYPE_SYSV
#define imake_ccflags "-DSYSV -I../../lib/X/mips -I/usr/include/bsd ../../lib/X/mips/mipssysvc.c -lbsd"
#endif
#endif

#else /* not CCIMAKE */
#ifndef MAKEDEPEND
/*
 * Step 2:  dup2
 *     If your OS doesn't have a dup2() system call to duplicate one file
 *     descriptor onto another, define such a mechanism here (if you don't
 *     already fall under the existing category(ies).
 */
#if defined(SYSV) && !defined(CRAY)
#define	dup2(fd1,fd2)	((fd1 == fd2) ? fd1 : (close(fd2), \
					       fcntl(fd1, F_DUPFD, fd2)))
#endif


/*
 * Step 3:  FIXUP_CPP_WHITESPACE
 *     If your cpp collapses tabs macro expansions into a single space and
 *     replaces escaped newlines with a space, define this symbol.  This will
 *     cause imake to attempt to patch up the generated Makefile by looking
 *     for lines that have colons in them (this is why the rules file escapes
 *     all colons).  One way to tell if you need this is to see whether or not
 *     your Makefiles have no tabs in them and lots of @@ strings.
 */
#if defined(sun) || defined(SYSV)
#define FIXUP_CPP_WHITESPACE
#endif


/*
 * Step 4:  DEFAULT_CPP
 *     If the C preprocessor does not live in /lib/cpp, set this symbol to 
 *     the appropriate location.
 */
#ifdef apollo
#define DEFAULT_CPP "/usr/lib/cpp"
#endif


/*
 * Step 5:  cpp_argv
 *     The following table contains the cpp flags that should be passed to 
 *     cpp whenever a Makefile is being generated.  If your preprocessor 
 *     doesn't predefine any unique symbols, choose one and add it to the
 *     end of this table.  Then, do the following:
 * 
 *         a.  Use this symbol at the top of Imake.tmpl when setting MacroFile.
 *         b.  Put this symbol in the definition of BootstrapCFlags in your
 *             <platform>.cf file.
 *         c.  When doing a make World, always add "BOOTSTRAPCFLAGS=-Dsymbol" 
 *             to the end of the command line.
 * 
 *     Note that you may define more than one symbols (useful for platforms 
 *     that support multiple operating systems).
 */

#define	ARGUMENTS 50	/* number of arguments in various arrays */
char *cpp_argv[ARGUMENTS] = {
	"cpp",		/* replaced by the actual cpp program to exec */
	"-I.",		/* add current directory to include path */
#ifdef unix
	"-Uunix",	/* remove unix symbol so that filename unix.c okay */
#endif
#ifdef M4330
	"-DM4330",	/* Tektronix */
#endif
#ifdef M4310
	"-DM4310",	/* Tektronix */
#endif
#ifdef macII
	"-DmacII",	/* Apple A/UX */
#endif
#ifdef att
	"-Datt",	/* AT&T products */
#endif
#ifdef aix
	"-Daix",	/* AIX instead of AOS */
#ifndef ibm
#define ibm		/* allow BOOTSTRAPCFLAGS="-Daix" */
#endif
#endif
#ifdef ibm
	"-Dibm",	/* IBM PS/2 and RT under both AOS and AIX */
#endif
};
#else /* else MAKEDEPEND */
/*
 * Step 6:  predefs
 *     If your compiler and/or preprocessor define any specific symbols, add
 *     them to the the following table.  The definition of struct symtab is
 *     in util/makedepend/main.c.
 */
struct symtab	predefs[] = {
#ifdef apollo
	{"apollo", "1"},
#endif
#ifdef ibm032
	{"ibm032", "1"},
#endif
#ifdef ibm
	{"ibm", "1"},
#endif
#ifdef aix
	{"aix", "1"},
#endif
#ifdef sun
	{"sun", "1"},
#endif
#ifdef hpux
	{"hpux", "1"},
#endif
#ifdef vax
	{"vax", "1"},
#endif
#ifdef VMS
	{"VMS", "1"},
#endif
#ifdef cray
	{"cray", "1"},
#endif
#ifdef CRAY
	{"CRAY", "1"},
#endif
#ifdef att
	{"att", "1"},
#endif
#ifdef mips
	{"mips", "1"},
#endif
#ifdef ultrix
	{"ultrix", "1"},
#endif
#ifdef stellar
	{"stellar", "1"},
#endif
#ifdef mc68000
	{"mc68000", "1"},
#endif
#ifdef mc68020
	{"mc68020", "1"},
#endif
#ifdef __GNUC__
	{"__GNUC__", "1"},
#endif
#ifdef __STDC__
	{"__STDC__", "1"},
#endif
#ifdef __HIGHC__
	{"__HIGHC__", "1"},
#endif
#ifdef CMU
	{"CMU", "1"},
#endif
	/* add any additional symbols before this line */
	{NULL, NULL}
};

#endif /* MAKEDEPEND */
#endif /* CCIMAKE */
