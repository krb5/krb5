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

#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#ifdef _WIN32
int fclose_socket(FILE* f);
FILE* fdopen_socket(SOCKET s, char* mode);
#define FCLOSE_SOCKET(f) fclose_socket(f)
#define FDOPEN_SOCKET(s, mode) fdopen_socket(s, mode)
#define SOCKETNO(fd) _get_osfhandle(fd)
#define PERROR_SOCKET(str) do { errno = SOCKET_ERRNO; perror(str); } while(0)
#else
#define FCLOSE_SOCKET(f) fclose(f)
#define FDOPEN_SOCKET(s, mode) fdopen(s, mode)
#define SOCKETNO(fd) (fd)
#define PERROR_SOCKET(str) perror(str)
#endif

#ifdef _WIN32
typedef void (*sig_t)(int);
typedef void sigtype;
#else
#define sig_t my_sig_t
#define sigtype krb5_sigtype
typedef sigtype (*sig_t)();
#endif

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
#ifdef _WIN32
#ifndef MAXPATHLEN
#define MAXPATHLEN MAX_PATH
#endif
#else
#include <sys/param.h>
#endif
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

extern char	line[500];	/* input line buffer */
extern char	*stringbase;	/* current scan point in line buffer */
extern char	argbuf[500];	/* argument storage buffer */
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
#ifndef _WIN32
extern	char *mktemp();
#endif

extern int command(char *, ...)
#if !defined(__cplusplus) && (__GNUC__ > 2)
    __attribute__((__format__(__printf__, 1, 2)))
#endif
    ;

char *remglob (char **, int);
int another (int *, char ***, char *);
void makeargv (void);
void setpeer (int, char **);
void setclevel (int, char **);
void setdlevel (int, char **);
void ccc (void);
void setclear (void);
void setsafe (void);
void setprivate (void);
void settype (int, char **);
void changetype (int, int);
void setbinary (void);
void setascii (void);
void settenex (void);
void set_mode  (int, char **);
void setform  (int, char **);
void setstruct  (int, char **);
void siteidle  (int, char **);
void put  (int, char **);
void mput  (int, char **);
void reget  (int, char **);
void get  (int, char **);
void mget  (int, char **);
void status  (int, char **);
void setbell (void);
void settrace (void);
void sethash (void);
void setverbose (void);
void setport (void);
void setprompt (void);
void setglob (void);
void setdebug (int, char **);
void cd (int, char **);
void lcd (int, char **);
void delete_file (int, char **);
void mdelete (int, char **);
void renamefile (int, char **);
void ls (int, char **);
void mls (int, char **);
void shell (int, char **);
void user (int, char **);
void pwd (void);
void makedir (int, char **);
void removedir (int, char **);
void quote (int, char **);
void site (int, char **);
void do_chmod (int, char **);
void do_umask (int, char **);
void setidle (int, char **);
void rmthelp (int, char **);
void quit (void);
void disconnect (void);
void fatal (char *);
void account (int, char **);
void doproxy (int, char **);
void setcase (void);
void setcr (void);
void setntrans (int, char **);
void setnmap (int, char **);
void setsunique (void);
void setrunique (void);
void cdup (void);
void restart (int, char **);
void syst (void);
void macdef (int, char **);
void sizecmd (int, char **);
void modtime (int, char **);
void rmtstatus (int, char **);
void newer (int, char **);
void setpassive (void);

/* ftp.c */
void sendrequest (char *, char *, char *, int);
void recvrequest (char *, char *volatile, char *, char *, int, int);
int login (char *);
void setpbsz (unsigned int);
void pswitch (int);
int getreply (int);
void reset (void);
char *hookup (char *, int);
int do_auth (void);

/* glob.c */
void blkfree (char **);

/* domacro.c */
void domacro (int, char **);


/* main.c */
void help (int, char **);
struct cmd *getcmd (char *);


/* ruserpass.c */
int ruserpass (char *, char **, char **, char **);

/* radix.h */
int radix_encode (unsigned char *, unsigned char *, int *, int);
char *radix_error (int);

/* getpass.c */
char *mygetpass (char *);

/* glob.c */
char **ftpglob (char *);
