/*
 * Copyright (c) 1985, 1989 Regents of the University of California.
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
 *
 *	@(#)ftp_var.h	5.9 (Berkeley) 6/1/90
 */

/*
 * FTP global variables.
 */

#ifdef DEFINITIONS
#define extern
#endif

/*
 * Options and other state info.
 */
extern int	trace;		/* trace packets exchanged */
extern int	hash;		/* print # for each buffer transferred */
extern int	sendport;	/* use PORT cmd for each data connection */
extern int	verbose;	/* print messages coming back from server */
extern int	connected;	/* connected to server */
extern int	fromatty;	/* input is from a terminal */
extern int	interactive;	/* interactively prompt on m* cmds */
extern int	debug;		/* debugging level */
extern int	bell;		/* ring bell on cmd completion */
extern int	doglob;		/* glob local file names */
extern int autoauth;		/* Do authentication on connect */
extern int	autologin;	/* establish user account on connection */
extern int	autoencrypt;	/* negotiate encryption on connection */
extern int	forward;	/* forward credentials */
extern int	proxy;		/* proxy server connection active */
extern int	proxflag;	/* proxy connection exists */
extern int	sunique;	/* store files on server with unique name */
extern int	runique;	/* store local files with unique name */
extern int	mcase;		/* map upper to lower case for mget names */
extern int	ntflag;		/* use ntin ntout tables for name translation */
extern int	mapflag;	/* use mapin mapout templates on file names */
extern int	code;		/* return/reply code for ftp command */
extern int	crflag;		/* if 1, strip car. rets. on ascii gets */
extern char	pasv[64];	/* passive port for proxy data connection */
#ifndef NO_PASSIVE_MODE
extern int	passivemode;	/* passive mode enabled */
#endif
extern char	*altarg;	/* argv[1] with no shell-like preprocessing  */
extern char	ntin[17];	/* input translation table */
extern char	ntout[17];	/* output translation table */
#include <sys/param.h>
extern char	mapin[MAXPATHLEN];	/* input map template */
extern char	mapout[MAXPATHLEN];	/* output map template */
extern int	clevel;		/* command channel protection level */
extern int	dlevel;		/* data channel protection level */
extern int	type;		/* requested file transfer type */
extern int	curtype;	/* current file transfer type */
extern int	stru;		/* file transfer structure */
extern int	form;		/* file transfer format */
extern int	mode;		/* file transfer mode */
extern char	bytename[32];	/* local byte size in ascii */
extern int	bytesize;	/* local byte size in binary */

extern char	*hostname;	/* name of host connected to */
extern int	unix_server;	/* server is unix, can use binary for ascii */
extern int	unix_proxy;	/* proxy is unix, can use binary for ascii */

extern struct	servent *sp;	/* service spec for tcp/ftp */

#include <setjmp.h>
extern jmp_buf	toplevel;	/* non-local goto stuff for cmd scanner */

extern char	line[200];	/* input line buffer */
extern char	*stringbase;	/* current scan point in line buffer */
extern char	argbuf[200];	/* argument storage buffer */
extern char	*argbase;	/* current storage point in arg buffer */
extern int	margc;		/* count of arguments on input line */
extern char	*margv[20];	/* args parsed from input line */
extern int     cpend;           /* flag: if != 0, then pending server reply */
extern int	mflag;		/* flag: if != 0, then active multi command */

extern int	options;	/* used during socket creation */

/*
 * Format of command table.
 */
struct cmd {
	char	*c_name;	/* name of command */
	char	*c_help;	/* help string */
	char	c_bell;		/* give bell when command completes */
	char	c_conn;		/* must be connected to use command */
	char	c_proxy;	/* proxy server may execute */
	void	(*c_handler)();	/* function to call */
};

struct macel {
	char mac_name[9];	/* macro name */
	char *mac_start;	/* start of macro in macbuf */
	char *mac_end;		/* end of macro in macbuf */
};

extern int macnum;		/* number of defined macros */
extern struct macel macros[16];
extern char macbuf[4096];

#ifdef DEFINITIONS
#undef extern
#endif

extern	char *tail();
extern	int errno;
extern	char *mktemp();

#if (defined(STDARG) || (defined(__STDC__) && ! defined(VARARGS))) || defined(HAVE_STDARG_H)
extern int command(char *, ...);
#endif

#define PROTOTYPE(x) x

char *remglob PROTOTYPE((char **, int));
int another PROTOTYPE((int *, char ***, char *));
void makeargv PROTOTYPE((void));
void setpeer PROTOTYPE((int, char **));
void setclevel PROTOTYPE((int, char **));
void setdlevel PROTOTYPE((int, char **));
void ccc PROTOTYPE((void));
void setclear PROTOTYPE((void));
void setsafe PROTOTYPE((void));
void setprivate PROTOTYPE((void));
void settype PROTOTYPE((int, char **));
void changetype PROTOTYPE((int, int));
void setbinary PROTOTYPE((void));
void setascii PROTOTYPE((void));
void settenex PROTOTYPE((void));
void set_mode  PROTOTYPE((int, char **));
void setform  PROTOTYPE((int, char **));
void setstruct  PROTOTYPE((int, char **));
void siteidle  PROTOTYPE((int, char **));
void put  PROTOTYPE((int, char **));
void mput  PROTOTYPE((int, char **));
void reget  PROTOTYPE((int, char **));
void get  PROTOTYPE((int, char **));
void mget  PROTOTYPE((int, char **));
void status  PROTOTYPE((int, char **));
void setbell PROTOTYPE((void));
void settrace PROTOTYPE((void));
void sethash PROTOTYPE((void));
void setverbose PROTOTYPE((void));
void setport PROTOTYPE((void));
void setprompt PROTOTYPE((void));
void setglob PROTOTYPE((void));
void setdebug PROTOTYPE((int, char **));
void cd PROTOTYPE((int, char **));
void lcd PROTOTYPE((int, char **));
void delete_file PROTOTYPE((int, char **));
void mdelete PROTOTYPE((int, char **));
void renamefile PROTOTYPE((int, char **));
void ls PROTOTYPE((int, char **));
void mls PROTOTYPE((int, char **));
void shell PROTOTYPE((int, char **));
void user PROTOTYPE((int, char **));
void pwd PROTOTYPE((void));
void makedir PROTOTYPE((int, char **));
void removedir PROTOTYPE((int, char **));
void quote PROTOTYPE((int, char **));
void site PROTOTYPE((int, char **));
void do_chmod PROTOTYPE((int, char **));
void do_umask PROTOTYPE((int, char **));
void setidle PROTOTYPE((int, char **));
void rmthelp PROTOTYPE((int, char **));
void quit PROTOTYPE((void));
void disconnect PROTOTYPE((void));
void fatal PROTOTYPE((char *));
void account PROTOTYPE((int, char **));
void doproxy PROTOTYPE((int, char **));
void setcase PROTOTYPE((void));
void setcr PROTOTYPE((void));
void setntrans PROTOTYPE((int, char **));
void setnmap PROTOTYPE((int, char **));
void setsunique PROTOTYPE((void));
void setrunique PROTOTYPE((void));
void cdup PROTOTYPE((void));
void restart PROTOTYPE((int, char **));
void syst PROTOTYPE((void));
void macdef PROTOTYPE((int, char **));
void sizecmd PROTOTYPE((int, char **));
void modtime PROTOTYPE((int, char **));
void rmtstatus PROTOTYPE((int, char **));
void newer PROTOTYPE((int, char **));
void setpassive PROTOTYPE((void));

/* ftp.c */
void sendrequest PROTOTYPE((char *, char *, char *, int));
void recvrequest PROTOTYPE((char *, char *, char *, char *, int));
int login PROTOTYPE((char *));
void setpbsz PROTOTYPE((unsigned int));
void pswitch PROTOTYPE((int));
int getreply PROTOTYPE((int));
void reset PROTOTYPE((void));
char *hookup PROTOTYPE((char *, int));
int do_auth PROTOTYPE((void));

/* glob.c */
void blkfree PROTOTYPE((char **));

/* domacro.c */
void domacro PROTOTYPE((int, char **));


/* main.c */
void help PROTOTYPE((int, char **));
struct cmd *getcmd PROTOTYPE((char *));


/* ruserpass.c */
int ruserpass PROTOTYPE((char *, char **, char **, char **));

/* radix.h */
int radix_encode PROTOTYPE((unsigned char *, unsigned char *, int *, int));
char *radix_error PROTOTYPE((int));

/* getpass.c */
char *mygetpass PROTOTYPE((char *));

/* glob.c */
char **ftpglob PROTOTYPE((char *));
