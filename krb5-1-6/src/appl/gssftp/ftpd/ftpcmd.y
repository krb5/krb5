/* -*- fundamental -*-
 * Copyright (c) 1985, 1988 Regents of the University of California.
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
 *	@(#)ftpcmd.y	5.24 (Berkeley) 2/25/91
 */

/*
 * Grammar for FTP commands.
 * See RFC 959.
 * See Also draft-ietf-cat-ftpsec-08.txt.
 */

%{

#ifndef lint
static char sccsid[] = "@(#)ftpcmd.y	5.24 (Berkeley) 2/25/91";
#endif /* not lint */


#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#ifdef HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/ftp.h>
#include <signal.h>
#include <setjmp.h>
#include <syslog.h>
#include <time.h>
#include <pwd.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "ftpd_var.h"

extern	char *auth_type;

unsigned int maxbuf, actualbuf;
unsigned char *ucbuf;

static int kerror;	/* XXX needed for all auth types */
#ifdef KRB5_KRB4_COMPAT
extern	struct sockaddr_in his_addr, ctrl_addr;
#include <krb.h>
extern AUTH_DAT kdata;
extern Key_schedule schedule;
extern MSG_DAT msg_data;
#endif /* KRB5_KRB4_COMPAT */
#ifdef GSSAPI
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_generic.h>
extern gss_ctx_id_t gcontext;
#endif

#ifndef unix
/* sigh */
#if defined(_AIX) || defined(__hpux) || defined(BSD)
#define unix
#endif
#endif

#ifndef NBBY
#define NBBY 8
#endif

static struct sockaddr_in host_port;

extern	struct sockaddr_in data_dest;
extern	int logged_in;
extern	struct passwd *pw;
extern	int guest;
extern	int logging;
extern	int type;
extern	int form;
extern	int clevel;
extern	int debug;


extern	int allow_ccc;
extern	int ccc_ok;
extern	int timeout;
extern	int maxtimeout;
extern  int pdata;
extern	int authlevel;
extern	char hostname[], remotehost[];
extern	char proctitle[];
extern	char *globerr;
extern	int usedefault;
extern  int transflag;
extern  char tmpline[];

char	**ftpglob();

off_t	restart_point;

static	int cmd_type;
static	int cmd_form;
static	int cmd_bytesz;
char	cbuf[FTP_BUFSIZ]; /* was 512 */
char	*fromname;

/* bison needs these decls up front */
extern jmp_buf errcatch;

#define	CMD	0	/* beginning of command */
#define	ARGS	1	/* expect miscellaneous arguments */
#define	STR1	2	/* expect SP followed by STRING */
#define	STR2	3	/* expect STRING */
#define	OSTR	4	/* optional SP then STRING */
#define	ZSTR1	5	/* SP then optional STRING */
#define	ZSTR2	6	/* optional STRING after SP */
#define	SITECMD	7	/* SITE command */
#define	NSTR	8	/* Number followed by a string */

struct tab {
	char	*name;
	short	token;
	short	state;
	short	implemented;	/* 1 if command is implemented */
	char	*help;
};
struct tab cmdtab[];
struct tab sitetab[];

void sizecmd(char *);
void help(struct tab *, char *);
static int yylex(void);
static char *copy(char *);
%}

%union { int num; char *str; }

%token
	SP	CRLF	COMMA	STRING	NUMBER

	USER	PASS	ACCT	REIN	QUIT	PORT
	PASV	TYPE	STRU	MODE	RETR	STOR
	APPE	MLFL	MAIL	MSND	MSOM	MSAM
	MRSQ	MRCP	ALLO	REST	RNFR	RNTO
	ABOR	DELE	CWD	LIST	NLST	SITE
	STAT	HELP	NOOP	MKD	RMD	PWD
	CDUP	STOU	SMNT	SYST	SIZE	MDTM
	AUTH	ADAT	PROT    PBSZ
	CCC

	UMASK	IDLE	CHMOD

	LEXERR

%type <num> NUMBER
%type <num> form_code prot_code struct_code mode_code octal_number
%type <num> check_login byte_size nonguest

%type <str> STRING
%type <str> password pathname username pathstring

%start	cmd_list

%%

cmd_list:	/* empty */
	|	cmd_list cmd
		{
			fromname = (char *) 0;
			restart_point = (off_t) 0;
		}
	|	cmd_list rcmd
	;

cmd:		USER SP username CRLF
		{
			user((char *) $3);
			free((char *) $3);
		}
	|	PASS SP password CRLF
		{
			pass((char *) $3);
			free((char *) $3);
		}
	|	PORT SP host_port CRLF
		{
			/*
			 * Don't allow a port < 1024 if we're not
			 * connecting back to the original source address
			 * This prevents nastier forms of the bounce attack.
			 */
			if (ntohs(host_port.sin_port) < 1024)
				reply(504, "Port number too low");
			else {
				data_dest = host_port;
				usedefault = 0;
				if (pdata >= 0) {
					(void) close(pdata);
					pdata = -1;
				}
				reply(200, "PORT command successful.");
			}
		}
	|	PASV check_login CRLF
		{
			if ($2)
				passive();
		}
	|	PROT SP prot_code CRLF
		{
		    if (maxbuf)
			setdlevel ($3);
		    else
			reply(503, "Must first set PBSZ");
		}
	|	CCC CRLF
		{
			if (!allow_ccc) {
			    reply(534, "CCC not supported");
			}
			else {
			    if(clevel == PROT_C && !ccc_ok) {
			        reply(533, "CCC command must be integrity protected");
			    } else {
			        reply(200, "CCC command successful.");
				ccc_ok = 1;
			    }
			}
		}
	|	PBSZ SP STRING CRLF
		{
			/* Others may want to do something more fancy here */
			if (!auth_type)
			    reply(503, "Must first perform authentication");
			else if (strlen($3) > 10 ||
				 (strlen($3) == 10 && 
				  strcmp($3,"4294967296") >= 0))
			    reply(501, "Bad value for PBSZ: %s", $3);
			else {
			    if (ucbuf) (void) free(ucbuf);
			    actualbuf = (unsigned int) atol($3);
			    /* I attempt what is asked for first, and if that
			       fails, I try dividing by 4 */
			    while ((ucbuf = (unsigned char *)malloc(actualbuf)) == NULL)
				if (actualbuf)
				    lreply(200, "Trying %u", actualbuf >>= 2);
				else {
				    perror_reply(421,
					"Local resource failure: malloc");
				    dologout(1);
				}
			    reply(200, "PBSZ=%u", maxbuf = actualbuf);
			}
		}
	|	TYPE SP type_code CRLF
		{
			switch (cmd_type) {

			case TYPE_A:
				if (cmd_form == FORM_N) {
					reply(200, "Type set to A.");
					type = cmd_type;
					form = cmd_form;
				} else
					reply(504, "Form must be N.");
				break;

			case TYPE_E:
				reply(504, "Type E not implemented.");
				break;

			case TYPE_I:
				reply(200, "Type set to I.");
				type = cmd_type;
				break;

			case TYPE_L:
#if NBBY == 8
				if (cmd_bytesz == 8) {
					reply(200,
					    "Type set to L (byte size 8).");
					type = cmd_type;
				} else
					reply(504, "Byte size must be 8.");
#else /* NBBY == 8 */
				UNIMPLEMENTED for NBBY != 8
#endif /* NBBY == 8 */
			}
		}
	|	STRU SP struct_code CRLF
		{
			switch ($3) {

			case STRU_F:
				reply(200, "STRU F ok.");
				break;

			default:
				reply(504, "Unimplemented STRU type.");
			}
		}
	|	MODE SP mode_code CRLF
		{
			switch ($3) {

			case MODE_S:
				reply(200, "MODE S ok.");
				break;

			default:
				reply(502, "Unimplemented MODE type.");
			}
		}
	|	ALLO SP NUMBER CRLF
		{
			reply(202, "ALLO command ignored.");
		}
	|	ALLO SP NUMBER SP 'R' SP NUMBER CRLF
		{
			reply(202, "ALLO command ignored.");
		}
	|	RETR check_login SP pathname CRLF
		{
			if ($2 && $4 != NULL)
				retrieve((char *) 0, (char *) $4);
			if ($4 != NULL)
				free((char *) $4);
		}
	|	STOR check_login SP pathname CRLF
		{
			if ($2 && $4 != NULL)
				store_file((char *) $4, "w", 0);
			if ($4 != NULL)
				free((char *) $4);
		}
	|	APPE check_login SP pathname CRLF
		{
			if ($2 && $4 != NULL)
				store_file((char *) $4, "a", 0);
			if ($4 != NULL)
				free((char *) $4);
		}
	|	NLST check_login CRLF
		{
			if ($2)
				send_file_list(".");
		}
	|	NLST check_login SP STRING CRLF
		{
			if ($2 && $4 != NULL) 
				send_file_list((char *) $4);
			if ($4 != NULL)
				free((char *) $4);
		}
	|	LIST check_login CRLF
		{
			if ($2)
				retrieve("/bin/ls -lgA", "");
		}
	|	LIST check_login SP pathname CRLF
		{
			if ($2 && $4 != NULL)
				retrieve("/bin/ls -lgA %s", (char *) $4);
			if ($4 != NULL)
				free((char *) $4);
		}
	|	STAT check_login SP pathname CRLF
		{
			if ($2 && $4 != NULL)
				statfilecmd((char *) $4);
			if ($4 != NULL)
				free((char *) $4);
		}
	|	STAT CRLF
		{
			statcmd();
		}
	|	DELE check_login SP pathname CRLF
		{
			if ($2 && $4 != NULL)
				delete_file((char *) $4);
			if ($4 != NULL)
				free((char *) $4);
		}
	|	RNTO SP pathname CRLF
		{
			if (fromname) {
				renamecmd(fromname, (char *) $3);
				free(fromname);
				fromname = (char *) 0;
			} else {
				reply(503, "Bad sequence of commands.");
			}
			free((char *) $3);
		}
	|	ABOR CRLF
		{
			reply(225, "ABOR command successful.");
		}
	|	CWD check_login CRLF
		{
			if ($2)
				cwd(pw->pw_dir);
		}
	|	CWD check_login SP pathname CRLF
		{
			if ($2 && $4 != NULL)
				cwd((char *) $4);
			if ($4 != NULL)
				free((char *) $4);
		}
	|	HELP CRLF
		{
			help(cmdtab, (char *) 0);
		}
	|	HELP SP STRING CRLF
		{
			register char *cp = (char *)$3;

			if (strncasecmp(cp, "SITE", 4) == 0) {
				cp = (char *)$3 + 4;
				if (*cp == ' ')
					cp++;
				if (*cp)
					help(sitetab, cp);
				else
					help(sitetab, (char *) 0);
			} else
				help(cmdtab, (char *) $3);
		}
	|	NOOP CRLF
		{
			reply(200, "NOOP command successful.");
		}
	|	MKD nonguest SP pathname CRLF
		{
			if ($2 && $4 != NULL)
				makedir((char *) $4);
			if ($4 != NULL)
				free((char *) $4);
		}
	|	RMD nonguest SP pathname CRLF
		{
			if ($2 && $4 != NULL)
				removedir((char *) $4);
			if ($4 != NULL)
				free((char *) $4);
		}
	|	PWD check_login CRLF
		{
			if ($2)
				pwd();
		}
	|	CDUP check_login CRLF
		{
			if ($2)
				cwd("..");
		}
	|	SITE SP HELP CRLF
		{
			help(sitetab, (char *) 0);
		}
	|	SITE SP HELP SP STRING CRLF
		{
			help(sitetab, (char *) $5);
		}
	|	SITE SP UMASK check_login CRLF
		{
			int oldmask;

			if ($4) {
				oldmask = umask(0);
				(void) umask(oldmask);
				reply(200, "Current UMASK is %03o", oldmask);
			}
		}
	|	SITE SP UMASK nonguest SP octal_number CRLF
		{
			int oldmask;

			if ($4) {
				if (($6 == -1) || ($6 > 0777)) {
					reply(501, "Bad UMASK value");
				} else {
					oldmask = umask($6);
					reply(200,
					    "UMASK set to %03o (was %03o)",
					    $6, oldmask);
				}
			}
		}
	|	SITE SP CHMOD nonguest SP octal_number SP pathname CRLF
		{
			if ($4 && ($8 != NULL)) {
				if ($6 > 0777)
					reply(501,
				"CHMOD: Mode value must be between 0 and 0777");
				else if (chmod((char *) $8, $6) < 0)
					perror_reply(550, (char *) $8);
				else
					reply(200, "CHMOD command successful.");
			}
			if ($8 != NULL)
				free((char *) $8);
		}
	|	SITE SP IDLE CRLF
		{
			reply(200,
			    "Current IDLE time limit is %d seconds; max %d",
				timeout, maxtimeout);
		}
	|	SITE SP IDLE SP NUMBER CRLF
		{
			if ($5 < 30 || $5 > maxtimeout) {
				reply(501,
			"Maximum IDLE time must be between 30 and %d seconds",
				    maxtimeout);
			} else {
				timeout = $5;
				(void) alarm((unsigned) timeout);
				reply(200,
				    "Maximum IDLE time set to %d seconds",
				    timeout);
			}
		}
	|	STOU check_login SP pathname CRLF
		{
			if ($2 && $4 != NULL)
				store_file((char *) $4, "w", 1);
			if ($4 != NULL)
				free((char *) $4);
		}
	|	SYST CRLF
		{
#ifdef unix
#ifdef __svr4__
#undef BSD
#endif
#ifdef BSD
			reply(215, "UNIX Type: L%d Version: BSD-%d",
				NBBY, BSD);
#else /* BSD */
			reply(215, "UNIX Type: L%d", NBBY);
#endif /* BSD */
#else /* unix */
			reply(215, "UNKNOWN Type: L%d", NBBY);
#endif /* unix */
		}

		/*
		 * SIZE is not in RFC959, but Postel has blessed it and
		 * it will be in the updated RFC.
		 *
		 * Return size of file in a format suitable for
		 * using with RESTART (we just count bytes).
		 */
	|	SIZE check_login SP pathname CRLF
		{
			if ($2 && $4 != NULL)
				sizecmd((char *) $4);
			if ($4 != NULL)
				free((char *) $4);
		}

		/*
		 * MDTM is not in RFC959, but Postel has blessed it and
		 * it will be in the updated RFC.
		 *
		 * Return modification time of file as an ISO 3307
		 * style time. E.g. YYYYMMDDHHMMSS or YYYYMMDDHHMMSS.xxx
		 * where xxx is the fractional second (of any precision,
		 * not necessarily 3 digits)
		 */
	|	MDTM check_login SP pathname CRLF
		{
			if ($2 && $4 != NULL) {
				struct stat stbuf;
				if (stat($4, &stbuf) < 0)
					perror_reply(550, $4);
				else if ((stbuf.st_mode&S_IFMT) != S_IFREG) {
					reply(550, "%s: not a plain file.",
						(char *) $4);
				} else {
					register struct tm *t;
					struct tm *gmtime();
					t = gmtime(&stbuf.st_mtime);
					reply(213,
					    "%4d%02d%02d%02d%02d%02d",
					    1900+t->tm_year, t->tm_mon+1, 
					    t->tm_mday, t->tm_hour, 
					    t->tm_min, t->tm_sec);
				}
			}
			if ($4 != NULL)
				free((char *) $4);
		}
	|	AUTH SP STRING CRLF
		{
			auth((char *) $3);
		}
	|	ADAT SP STRING CRLF
		{
			auth_data((char *) $3);
			free((char *) $3);
		}
	|	QUIT CRLF
		{
			reply(221, "Goodbye.");
			dologout(0);
		}
	|	error CRLF
		{
			yyerrok;
		}
	;
rcmd:		RNFR check_login SP pathname CRLF
		{
			restart_point = (off_t) 0;
			if ($2 && $4) {
				fromname = renamefrom((char *) $4);
				if (fromname == (char *) 0 && $4) {
					free((char *) $4);
				}
			}
		}
	|	REST SP byte_size CRLF
		{
			fromname = (char *) 0;
			restart_point = $3;
			reply(350, "Restarting at %ld. %s", 
			      (long) restart_point,
			      "Send STORE or RETRIEVE to initiate transfer.");
		}
	;
		
username:	STRING
	;

password:	/* empty */
		{
			*(char **)&($$) = (char *)calloc(1, sizeof(char));
		}
	|	STRING
	;

byte_size:	NUMBER
	;

host_port:	NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA 
		NUMBER COMMA NUMBER
		{
			register char *a, *p;

			a = (char *)&host_port.sin_addr;
			a[0] = $1; a[1] = $3; a[2] = $5; a[3] = $7;
			p = (char *)&host_port.sin_port;
			p[0] = $9; p[1] = $11;
			host_port.sin_family = AF_INET;
		}
	;

form_code:	'N'
	{
		$$ = FORM_N;
	}
	|	'T'
	{
		$$ = FORM_T;
	}
	|	'C'
	{
		$$ = FORM_C;
	}
	;

prot_code:	'C'
	{
		$$ = PROT_C;
	}
	|	'S'
	{
		$$ = PROT_S;
	}
	|	'P'
	{
		$$ = PROT_P;
	}
	|	'E'
	{
		$$ = PROT_E;
	}
	;

type_code:	'A'
	{
		cmd_type = TYPE_A;
		cmd_form = FORM_N;
	}
	|	'A' SP form_code
	{
		cmd_type = TYPE_A;
		cmd_form = $3;
	}
	|	'E'
	{
		cmd_type = TYPE_E;
		cmd_form = FORM_N;
	}
	|	'E' SP form_code
	{
		cmd_type = TYPE_E;
		cmd_form = $3;
	}
	|	'I'
	{
		cmd_type = TYPE_I;
	}
	|	'L'
	{
		cmd_type = TYPE_L;
		cmd_bytesz = NBBY;
	}
	|	'L' SP byte_size
	{
		cmd_type = TYPE_L;
		cmd_bytesz = $3;
	}
	/* this is for a bug in the BBN ftp */
	|	'L' byte_size
	{
		cmd_type = TYPE_L;
		cmd_bytesz = $2;
	}
	;

struct_code:	'F'
	{
		$$ = STRU_F;
	}
	|	'R'
	{
		$$ = STRU_R;
	}
	|	'P'
	{
		$$ = STRU_P;
	}
	;

mode_code:	'S'
	{
		$$ = MODE_S;
	}
	|	'B'
	{
		$$ = MODE_B;
	}
	|	'C'
	{
		$$ = MODE_C;
	}
	;

pathname:	pathstring
	{
		/*
		 * Problem: this production is used for all pathname
		 * processing, but only gives a 550 error reply.
		 * This is a valid reply in some cases but not in others.
		 */
		if (logged_in && $1 && strncmp((char *) $1, "~", 1) == 0) {
			char **vv;

			vv = ftpglob((char *) $1);
			$$ = (vv != NULL) ? *vv : NULL;
			if ($$ == NULL) {
				if (globerr == NULL)
					$$ = $1;
				else {
					reply(550, "%s", globerr);
					free((char *) $1);
				}
			} else
				free((char *) $1);
		} else
			$$ = $1;
	}
	;

pathstring:	STRING
	;

octal_number:	NUMBER
	{
		register int ret, dec, multby, digit;

		/*
		 * Convert a number that was read as decimal number
		 * to what it would be if it had been read as octal.
		 */
		dec = $1;
		multby = 1;
		ret = 0;
		while (dec) {
			digit = dec%10;
			if (digit > 7) {
				ret = -1;
				break;
			}
			ret += digit * multby;
			multby *= 8;
			dec /= 10;
		}
		$$ = ret;
	}
	;

check_login:	/* empty */
	{
		if (logged_in)
			$$ = 1;
		else {
			reply(530, "Please login with USER and PASS.");
			$$ = 0;
		}
	}
	;

nonguest: check_login
	{
		if (guest) {
			reply(550, "Operation prohibited for anonymous users.");
			$$ = 0;
		}
		else
			$$ = $1;
	}
	;
%%

struct tab cmdtab[] = {		/* In order defined in RFC 765 */
	{ "USER", USER, STR1, 1,	"<sp> username" },
	{ "PASS", PASS, ZSTR1, 1,	"<sp> password" },
	{ "ACCT", ACCT, STR1, 0,	"(specify account)" },
	{ "SMNT", SMNT, ARGS, 0,	"(structure mount)" },
	{ "REIN", REIN, ARGS, 0,	"(reinitialize server state)" },
	{ "QUIT", QUIT, ARGS, 1,	"(terminate service)", },
	{ "PORT", PORT, ARGS, 1,	"<sp> b0, b1, b2, b3, b4" },
	{ "PASV", PASV, ARGS, 1,	"(set server in passive mode)" },
	{ "TYPE", TYPE, ARGS, 1,	"<sp> [ A | E | I | L ]" },
	{ "STRU", STRU, ARGS, 1,	"(specify file structure)" },
	{ "MODE", MODE, ARGS, 1,	"(specify transfer mode)" },
	{ "RETR", RETR, STR1, 1,	"<sp> file-name" },
	{ "STOR", STOR, STR1, 1,	"<sp> file-name" },
	{ "APPE", APPE, STR1, 1,	"<sp> file-name" },
	{ "MLFL", MLFL, OSTR, 0,	"(mail file)" },
	{ "MAIL", MAIL, OSTR, 0,	"(mail to user)" },
	{ "MSND", MSND, OSTR, 0,	"(mail send to terminal)" },
	{ "MSOM", MSOM, OSTR, 0,	"(mail send to terminal or mailbox)" },
	{ "MSAM", MSAM, OSTR, 0,	"(mail send to terminal and mailbox)" },
	{ "MRSQ", MRSQ, OSTR, 0,	"(mail recipient scheme question)" },
	{ "MRCP", MRCP, STR1, 0,	"(mail recipient)" },
	{ "ALLO", ALLO, ARGS, 1,	"allocate storage (vacuously)" },
	{ "REST", REST, ARGS, 1,	"(restart command)" },
	{ "RNFR", RNFR, STR1, 1,	"<sp> file-name" },
	{ "RNTO", RNTO, STR1, 1,	"<sp> file-name" },
	{ "ABOR", ABOR, ARGS, 1,	"(abort operation)" },
	{ "DELE", DELE, STR1, 1,	"<sp> file-name" },
	{ "CWD",  CWD,  OSTR, 1,	"[ <sp> directory-name ]" },
	{ "XCWD", CWD,	OSTR, 1,	"[ <sp> directory-name ]" },
	{ "LIST", LIST, OSTR, 1,	"[ <sp> path-name ]" },
	{ "NLST", NLST, OSTR, 1,	"[ <sp> path-name ]" },
	{ "SITE", SITE, SITECMD, 1,	"site-cmd [ <sp> arguments ]" },
	{ "SYST", SYST, ARGS, 1,	"(get type of operating system)" },
	{ "STAT", STAT, OSTR, 1,	"[ <sp> path-name ]" },
	{ "HELP", HELP, OSTR, 1,	"[ <sp> <string> ]" },
	{ "NOOP", NOOP, ARGS, 1,	"" },
	{ "MKD",  MKD,  STR1, 1,	"<sp> path-name" },
	{ "XMKD", MKD,  STR1, 1,	"<sp> path-name" },
	{ "RMD",  RMD,  STR1, 1,	"<sp> path-name" },
	{ "XRMD", RMD,  STR1, 1,	"<sp> path-name" },
	{ "PWD",  PWD,  ARGS, 1,	"(return current directory)" },
	{ "XPWD", PWD,  ARGS, 1,	"(return current directory)" },
	{ "CDUP", CDUP, ARGS, 1,	"(change to parent directory)" },
	{ "XCUP", CDUP, ARGS, 1,	"(change to parent directory)" },
	{ "STOU", STOU, STR1, 1,	"<sp> file-name" },
	{ "AUTH", AUTH, STR1, 1,	"<sp> auth-type" },
	{ "ADAT", ADAT, STR1, 1,	"<sp> auth-data" },
	{ "PROT", PROT, ARGS, 1,	"<sp> protection-level" },
	{ "PBSZ", PBSZ, STR1, 1,	"<sp> buffer-size" },
	{ "CCC",  CCC,  ARGS, 1,	"(clear command channel)" },
	{ "SIZE", SIZE, OSTR, 1,	"<sp> path-name" },
	{ "MDTM", MDTM, OSTR, 1,	"<sp> path-name" },
	{ NULL,   0,    0,    0,	0 }
};

struct tab sitetab[] = {
	{ "UMASK", UMASK, ARGS, 1,	"[ <sp> umask ]" },
	{ "IDLE", IDLE, ARGS, 1,	"[ <sp> maximum-idle-time ]" },
	{ "CHMOD", CHMOD, NSTR, 1,	"<sp> mode <sp> file-name" },
	{ "HELP", HELP, OSTR, 1,	"[ <sp> <string> ]" },
	{ NULL,   0,    0,    0,	0 }
};

static struct tab *
lookup(p, cmd)
	register struct tab *p;
	char *cmd;
{

	for (; p->name != NULL; p++)
		if (strcmp(cmd, p->name) == 0)
			return (p);
	return (0);
}

/*
 * urgsafe_getc - hacked up getc to ignore EOF if SIOCATMARK returns TRUE
 */
static int
urgsafe_getc(f)
	FILE *f;
{
	register int c;
	int atmark;

	c = getc(f);
	if (c == EOF) {
		if (ioctl(fileno(f), SIOCATMARK, &atmark) != -1) {
			c = getc(f);
			syslog(LOG_DEBUG, "atmark: c=%d", c);
		}
	}
	return c;
}

#include <arpa/telnet.h>

/*
 * getline - a hacked up version of fgets to ignore TELNET escape codes.
 */
char *
ftpd_getline(s, n, iop)
	char *s;
	int n;
	register FILE *iop;
{
	register int c;
	register char *cs;

	cs = s;
/* tmpline may contain saved command from urgent mode interruption */
	for (c = 0; tmpline[c] != '\0' && --n > 0; ++c) {
		*cs++ = tmpline[c];
		if (tmpline[c] == '\n') {
			*cs++ = '\0';
			if (debug)
				syslog(LOG_DEBUG, "command: %s", s);
			tmpline[0] = '\0';
			return(s);
		}
		if (c == 0)
			tmpline[0] = '\0';
	}
	while ((c = urgsafe_getc(iop)) != EOF) {
		c &= 0377;
		if (c == IAC) {
			if (debug) syslog(LOG_DEBUG, "got IAC");
		    if ((c = urgsafe_getc(iop)) != EOF) {
			c &= 0377;
			if (debug) syslog(LOG_DEBUG, "got IAC %d", c);
			switch (c) {
			case WILL:
			case WONT:
				c = urgsafe_getc(iop);
				printf("%c%c%c", IAC, DONT, 0377&c);
				(void) fflush(stdout);
				continue;
			case DO:
			case DONT:
				c = urgsafe_getc(iop);
				printf("%c%c%c", IAC, WONT, 0377&c);
				(void) fflush(stdout);
				continue;
			case IAC:
				break;
			default:
				continue;	/* ignore command */
			}
		    }
		}
		*cs++ = c;
		if (--n <= 0 || c == '\n')
			break;
	}
	if (c == EOF && cs == s)
		return (NULL);
	*cs++ = '\0';
	if (auth_type) {
	    char out[sizeof(cbuf)], *cp;
	    int len, mic;


	    /* Check to see if we have a protected command. */
	    if (!((mic = strncmp(s, "ENC", 3)) && strncmp(s, "MIC", 3)
		&& strncmp(s, "AUTH", 4)
#ifndef NOCONFIDENTIAL
	        && strncmp(s, "CONF", 4)
#endif
	        ) && (cs = strpbrk(s, " \r\n"))) {
	    	    *cs++ = '\0'; /* If so, split it into s and cs. */
	    } else { /* If not, check if unprotected commands are allowed. */
		if(ccc_ok) {
		    clevel = PROT_C;
		    upper(s);
		    return(s);
		} else {
		    reply(533, "All commands must be protected.");
		    syslog(LOG_ERR, "Unprotected command received");
		    *s = '\0';
		    return(s);
		}
	    }
	    upper(s);
	    if (debug)
	        syslog(LOG_INFO, "command %s received (mic=%d)", s, mic);
#ifdef NOCONFIDENTIAL
	    if (!strcmp(s, "CONF")) {
		reply(537, "CONF protected commands not supported.");
		*s = '\0';
		return(s);
	    }
#endif
/* Some paranoid sites may want to require that commands be encrypted. */
#ifdef PARANOID
	    if (mic) {
		reply(533, "All commands must be ENC protected.  Retry command under ENC.");
		*s = '\0';
		return(s);
	    }
#endif /* PARANOID */
#ifdef NOENCRYPTION
	    if (!mic) {
		reply(533, "ENC protection not supported.  Retry command under MIC.");
		*s = '\0';
		return(s);
	    }
#endif /* NOENCRYPTION */
	    if ((cp = strpbrk(cs, " \r\n")))
		*cp = '\0';
	    kerror = radix_encode(cs, out, &len, 1);
	    if (kerror) {
		reply(501, "Can't base 64 decode argument to %s command (%s)",
		      mic ? "MIC" : "ENC", radix_error(kerror));
		*s = '\0';
		return(s);
	    }
	    if (debug) syslog(LOG_DEBUG, "getline got %d from %s <%s>\n", 
			      len, cs, mic?"MIC":"ENC");
	    clevel = mic ? PROT_S : PROT_P;
#ifdef KRB5_KRB4_COMPAT
	    if (strcmp(auth_type, "KERBEROS_V4") == 0) {
		if ((kerror = mic ?
		    krb_rd_safe((unsigned char *)out, len, &kdata.session,
			    &his_addr, &ctrl_addr, &msg_data)
		  : krb_rd_priv((unsigned char *)out, len, schedule,
			    &kdata.session, &his_addr, &ctrl_addr, &msg_data))
			!= KSUCCESS) {
		    reply(535, "%s! (%s)",
			   mic ? "MIC command modified" : "ENC command garbled",
			   krb_get_err_text(kerror));
		    syslog(LOG_ERR,"%s failed: %s",
			   mic ? "MIC krb_rd_safe" : "ENC krb_rd_priv",
			   krb_get_err_text(kerror));
		    *s = '\0';
		    return(s);
		}
		(void) memcpy(s, msg_data.app_data, msg_data.app_length);
		(void) strcpy(s+msg_data.app_length, "\r\n");
	    }
#endif /* KRB5_KRB4_COMPAT */
#ifdef GSSAPI
/* we know this is a MIC or ENC already, and out/len already has the bits */
	    if (strcmp(auth_type, "GSSAPI") == 0) {
		gss_buffer_desc xmit_buf, msg_buf;
		OM_uint32 maj_stat, min_stat;
		int conf_state;

		xmit_buf.value = out;
		xmit_buf.length = len;
		/* decrypt the message */
		conf_state = !mic;
		maj_stat = gss_unseal(&min_stat, gcontext, &xmit_buf,
				      &msg_buf, &conf_state, NULL);
		if (maj_stat == GSS_S_CONTINUE_NEEDED) {
			if (debug) syslog(LOG_DEBUG, "%s-unseal continued", 
					  mic?"MIC":"ENC");
			reply(535, "%s-unseal continued, oops",
			      mic?"MIC":"ENC");
			*s = 0; return s;
		}
		if (maj_stat != GSS_S_COMPLETE) {
			reply_gss_error(535, maj_stat, min_stat, 
					mic? "failed unsealing MIC message":
					"failed unsealing ENC message");
			*s = 0;
			return s;
		}

		memcpy(s, msg_buf.value, msg_buf.length);
		strcpy(s+msg_buf.length-(s[msg_buf.length-1]?0:1), "\r\n");
		gss_release_buffer(&min_stat, &msg_buf);
	    }
#endif /* GSSAPI */
	    /* Other auth types go here ... */

	    /* A password should never be MICed, but the CNS ftp
	     * client and the pre-6/98 Krb5 client did this if you
	     * authenticated but didn't encrypt.
	     */
	    if (authlevel && mic && !strncmp(s, "PASS", 4)) {
	    	lreply(530, "There is a problem with your ftp client. Password refused.");
		reply(530, "Enable encryption before logging in, or update your ftp program.");
		*s = 0;
		return s;
	    }

	}
#if defined KRB5_KRB4_COMPAT || defined GSSAPI	/* or other auth types */
	else {	/* !auth_type */
	    if ( (!(strncmp(s, "ENC", 3))) || (!(strncmp(s, "MIC", 3)))
#ifndef NOCONFIDENTIAL
                || (!(strncmp(s, "CONF", 4)))
#endif
                                        ) {
                reply(503, "Must perform authentication before sending protected commands");
                *s = '\0';
                return(s);
	    }
	}
#endif /* KRB5_KRB4_COMPAT || GSSAPI */

	if (debug) {
		if (!strncmp(s, "PASS ", 5) && !guest)
			syslog(LOG_DEBUG, "command: <PASS XXX>");
		else
			syslog(LOG_DEBUG, "command: <%.*s>(%d)",
			       strlen(s) - 2, s, strlen(s));
	}
	return (s);
}

static krb5_sigtype
toolong(sig)
	int sig;
{
	time_t now;

	reply(421,
	  "Timeout (%d seconds): closing control connection.", timeout);
	(void) time(&now);
	if (logging) {
		syslog(LOG_INFO,
			"User %s timed out after %d seconds at %s",
			(pw ? pw -> pw_name : "unknown"), timeout, ctime(&now));
	}
	dologout(1);
}

static int
yylex()
{
	static int cpos, state;
	register char *cp, *cp2;
	register struct tab *p;
	int n;
	char c;

	for (;;) {
		switch (state) {

		case CMD:
			(void) signal(SIGALRM, toolong);
			(void) alarm((unsigned) timeout);
			if (ftpd_getline(cbuf, sizeof(cbuf)-1, stdin) == NULL) {
				reply(221, "You could at least say goodbye.");
				dologout(0);
			}
			(void) alarm(0);

			/* If getline() finds an error, the string is null */
			if (*cbuf == '\0')
				continue;

#ifdef SETPROCTITLE
			if (strncasecmp(cbuf, "PASS", 4) != NULL)
				setproctitle("%s: %s", proctitle, cbuf);
#endif /* SETPROCTITLE */
			if ((cp = strchr(cbuf, '\r'))) {
				*cp++ = '\n';
				*cp = '\0';
			}
			if ((cp = strpbrk(cbuf, " \n")))
				cpos = cp - cbuf;
			if (cpos == 0)
				cpos = 4;
			c = cbuf[cpos];
			cbuf[cpos] = '\0';
			upper(cbuf);
			p = lookup(cmdtab, cbuf);
			cbuf[cpos] = c;
			if (p != 0) {
				if (p->implemented == 0) {
					nack(p->name);
					longjmp(errcatch,0);
					/* NOTREACHED */
				}
				state = p->state;
				yylval.str = p->name;
				return (p->token);
			}
			break;

		case SITECMD:
			if (cbuf[cpos] == ' ') {
				cpos++;
				return (SP);
			}
			cp = &cbuf[cpos];
			if ((cp2 = strpbrk(cp, " \n")))
				cpos = cp2 - cbuf;
			c = cbuf[cpos];
			cbuf[cpos] = '\0';
			upper(cp);
			p = lookup(sitetab, cp);
			cbuf[cpos] = c;
			if (p != 0) {
				if (p->implemented == 0) {
					state = CMD;
					nack(p->name);
					longjmp(errcatch,0);
					/* NOTREACHED */
				}
				state = p->state;
				yylval.str = p->name;
				return (p->token);
			}
			state = CMD;
			break;

		case OSTR:
			if (cbuf[cpos] == '\n') {
				state = CMD;
				return (CRLF);
			}
			/* FALLTHROUGH */

		case STR1:
		case ZSTR1:
		dostr1:
			if (cbuf[cpos] == ' ') {
				cpos++;
				state = state == OSTR ? STR2 : state+1;
				return (SP);
			}
			break;

		case ZSTR2:
			if (cbuf[cpos] == '\n') {
				state = CMD;
				return (CRLF);
			}
			/* FALLTHROUGH */

		case STR2:
			cp = &cbuf[cpos];
			n = strlen(cp);
			cpos += n - 1;
			/*
			 * Make sure the string is nonempty and \n terminated.
			 */
			if (n > 1 && cbuf[cpos] == '\n') {
				cbuf[cpos] = '\0';
				yylval.str = copy(cp);
				cbuf[cpos] = '\n';
				state = ARGS;
				return (STRING);
			}
			break;

		case NSTR:
			if (cbuf[cpos] == ' ') {
				cpos++;
				return (SP);
			}
			if (isdigit((int) cbuf[cpos])) {
				cp = &cbuf[cpos];
				while (isdigit((int) cbuf[++cpos]))
					;
				c = cbuf[cpos];
				cbuf[cpos] = '\0';
				yylval.num = atoi(cp);
				cbuf[cpos] = c;
				state = STR1;
				return (NUMBER);
			}
			state = STR1;
			goto dostr1;

		case ARGS:
			if (isdigit((int) cbuf[cpos])) {
				cp = &cbuf[cpos];
				while (isdigit((int) cbuf[++cpos]))
					;
				c = cbuf[cpos];
				cbuf[cpos] = '\0';
				yylval.num = atoi(cp);
				cbuf[cpos] = c;
				return (NUMBER);
			}
			switch (cbuf[cpos++]) {

			case '\n':
				state = CMD;
				return (CRLF);

			case ' ':
				return (SP);

			case ',':
				return (COMMA);

			case 'A':
			case 'a':
				return ('A');

			case 'B':
			case 'b':
				return ('B');

			case 'C':
			case 'c':
				return ('C');

			case 'E':
			case 'e':
				return ('E');

			case 'F':
			case 'f':
				return ('F');

			case 'I':
			case 'i':
				return ('I');

			case 'L':
			case 'l':
				return ('L');

			case 'N':
			case 'n':
				return ('N');

			case 'P':
			case 'p':
				return ('P');

			case 'R':
			case 'r':
				return ('R');

			case 'S':
			case 's':
				return ('S');

			case 'T':
			case 't':
				return ('T');

			}
			break;

		default:
			fatal("Unknown state in scanner.");
		}
		yyerror((char *) 0);
		state = CMD;
		longjmp(errcatch,0);
	}
}

void
upper(s)
	register char *s;
{
	while (*s != '\0') {
		if (islower((int) (*s)))
			*s = toupper((int) (*s));
		s++;
	}
}

static char *
copy(s)
	char *s;
{
	char *p;

	p = malloc((unsigned) strlen(s) + 1);
	if (p == NULL)
		fatal("Ran out of memory.");
	(void) strcpy(p, s);
	return (p);
}

void
help(ctab, s)
	struct tab *ctab;
	char *s;
{
	register struct tab *c;
	register int width, NCMDS;
	char str[80];
	char *ftype;

	if (ctab == sitetab)
		ftype = "SITE ";
	else
		ftype = "";
	width = 0, NCMDS = 0;
	for (c = ctab; c->name != NULL; c++) {
		int len = strlen(c->name);

		if (len > width)
			width = len;
		NCMDS++;
	}
	width = (width + 8) &~ 7;
	if (s == 0) {
		register int i, j, w;
		int columns, lines;

		lreply(214, "The following %scommands are recognized %s.",
		    ftype, "(* =>'s unimplemented)");
		columns = 76 / width;
		if (columns == 0)
			columns = 1;
		lines = (NCMDS + columns - 1) / columns;
		for (i = 0; i < lines; i++) {
			strcpy(str, "   ");
			for (j = 0; j < columns; j++) {
				c = ctab + j * lines + i;
				sprintf(&str[strlen(str)], "%s%c", c->name,
					c->implemented ? ' ' : '*');
				if (c + lines >= &ctab[NCMDS])
					break;
				w = strlen(c->name) + 1;
				while (w < width) {
					strcat(str, " ");
					w++;
				}
			}
			reply(0, "%s", str);
		}
		reply(214, "Direct comments to ftp-bugs@%s.", hostname);
		return;
	}
	upper(s);
	c = lookup(ctab, s);
	if (c == (struct tab *)0) {
		reply(502, "Unknown command %s.", s);
		return;
	}
	if (c->implemented)
		reply(214, "Syntax: %s%s %s", ftype, c->name, c->help);
	else
		reply(214, "%s%-*s\t%s; unimplemented.", ftype, width,
		    c->name, c->help);
}

void
sizecmd(filename)
char *filename;
{
	switch (type) {
	case TYPE_L:
	case TYPE_I: {
		struct stat stbuf;
		if (stat(filename, &stbuf) < 0 ||
		    (stbuf.st_mode&S_IFMT) != S_IFREG)
			reply(550, "%s: not a plain file.", filename);
		else
			reply(213, "%lu", (long) stbuf.st_size);
		break;}
	case TYPE_A: {
		FILE *fin;
		register int c;
		register long count;
		struct stat stbuf;
		fin = fopen(filename, "r");
		if (fin == NULL) {
			perror_reply(550, filename);
			return;
		}
		if (fstat(fileno(fin), &stbuf) < 0 ||
		    (stbuf.st_mode&S_IFMT) != S_IFREG) {
			reply(550, "%s: not a plain file.", filename);
			(void) fclose(fin);
			return;
		}

		count = 0;
		while((c=getc(fin)) != EOF) {
			if (c == '\n')	/* will get expanded to \r\n */
				count++;
			count++;
		}
		(void) fclose(fin);

		reply(213, "%ld", count);
		break;}
	default:
		reply(504, "SIZE not implemented for Type %c.", "?AEIL"[type]);
	}
}
