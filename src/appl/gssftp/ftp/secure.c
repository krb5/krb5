/*
 * Shared routines for client and server for
 * secure read(), write(), getc(), and putc().
 * Only one security context, thus only work on one fd at a time!
 */

#include <secure.h>	/* stuff which is specific to client or server */

#ifdef KRB5_KRB4_COMPAT
#include <krb.h>

CRED_DECL
extern KTEXT_ST ticket;
extern MSG_DAT msg_data;
extern Key_schedule schedule;
#endif /* KRB5_KRB4_COMPAT */
#ifdef GSSAPI
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_generic.h>
extern gss_ctx_id_t gcontext;
#endif /* GSSAPI */

#include <arpa/ftp.h>

#include <stdio.h>
#include <string.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <sys/types.h>
#include <netinet/in.h>
#include <errno.h>

#ifdef NEED_SYS_ERRLIST
extern char *sys_errlist[];
#endif

#if (SIZEOF_SHORT == 4)
typedef unsigned short ftp_uint32;
typedef short ftp_int32;
#elif (SIZEOF_INT == 4)
typedef unsigned int ftp_uint32;
typedef int ftp_int32;
#elif (SIZEOF_LONG == 4)
typedef unsigned long ftp_uint32;
typedef long ftp_int32;
#endif


extern struct	sockaddr_in hisaddr;
extern struct	sockaddr_in myaddr;
extern int	level;
extern char	*auth_type;

#define MAX maxbuf
extern unsigned int maxbuf; 	/* maximum output buffer size */
extern unsigned char *ucbuf;	/* cleartext buffer */
static unsigned int nout, bufp;	/* number of chars in ucbuf,
				 * pointer into ucbuf */

#ifdef KRB5_KRB4_COMPAT
#define FUDGE_FACTOR 32		/* Amount of growth
				 * from cleartext to ciphertext.
				 * krb_mk_priv adds this # bytes.
				 * Must be defined for each auth type.
				 */
#endif /* KRB5_KRB4_COMPAT */

#ifdef GSSAPI
#undef FUDGE_FACTOR
#define FUDGE_FACTOR 64 /*It appears to add 52 byts, but I'm not usre it is a constant--hartmans*/
#endif /*GSSAPI*/

#ifndef FUDGE_FACTOR		/* In case no auth types define it. */
#define FUDGE_FACTOR 0
#endif

#ifdef KRB5_KRB4_COMPAT
/* XXX - The following must be redefined if KERBEROS_V4 is not used
 * but some other auth type is.  They must have the same properties. */
#define looping_write krb_net_write
#define looping_read krb_net_read
#endif

/* perhaps use these in general, certainly use them for GSSAPI */

#ifndef looping_write
static int
looping_write(fd, buf, len)
    int fd;
    register const char *buf;
    int len;
{
    int cc;
    register int wrlen = len;
    do {
	cc = write(fd, buf, wrlen);
	if (cc < 0) {
	    if (errno == EINTR)
		continue;
	    return(cc);
	}
	else {
	    buf += cc;
	    wrlen -= cc;
	}
    } while (wrlen > 0);
    return(len);
}
#endif
#ifndef looping_read
static int
looping_read(fd, buf, len)
    int fd;
    register char *buf;
    register int len;
{
    int cc, len2 = 0;

    do {
	cc = read(fd, buf, len);
	if (cc < 0) {
	    if (errno == EINTR)
		continue;
	    return(cc);		 /* errno is already set */
	}		
	else if (cc == 0) {
	    return(len2);
	} else {
	    buf += cc;
	    len2 += cc;
	    len -= cc;
	}
    } while (len > 0);
    return(len2);
}
#endif


#if defined(STDARG) || (defined(__STDC__) && ! defined(VARARGS)) || defined(HAVE_STDARG_H)
extern secure_error(char *, ...);
#else
extern secure_error();
#endif

#define ERR	-2

static
secure_putbyte(fd, c)
int fd;
unsigned char c;
{
	int ret;

	ucbuf[nout++] = c;
	if (nout == MAX - FUDGE_FACTOR) {
	  ret = secure_putbuf(fd, ucbuf, nout);
	  nout = 0;
	  return(ret?ret:c);
	}
return (c);
}

/* returns:
 *	 0  on success
 *	-1  on error (errno set)
 *	-2  on security error
 */
secure_flush(fd)
int fd;
{
	int ret;

	if (level == PROT_C)
		return(0);
	if (nout)
		if (ret = secure_putbuf(fd, ucbuf, nout))
			return(ret);
	return(secure_putbuf(fd, "", nout = 0));
}

/* returns:
 *	c>=0  on success
 *	-1    on error
 *	-2    on security error
 */
secure_putc(c, stream)
char c;
FILE *stream;
{
	if (level == PROT_C)
		return(putc(c,stream));
	return(secure_putbyte(fileno(stream), (unsigned char) c));
}

/* returns:
 *	nbyte on success
 *	-1  on error (errno set)
 *	-2  on security error
 */
secure_write(fd, buf, nbyte)
int fd;
unsigned char *buf;
unsigned int nbyte;
{
	unsigned int i;
	int c;

	if (level == PROT_C)
		return(write(fd,buf,nbyte));
	for (i=0; nbyte>0; nbyte--)
		if ((c = secure_putbyte(fd, buf[i++])) < 0)
			return(c);
	return(i);
}

/* returns:
 *	 0  on success
 *	-1  on error (errno set)
 *	-2  on security error
 */
secure_putbuf(fd, buf, nbyte)
  int fd;
unsigned char *buf;
unsigned int nbyte;
{
	static char *outbuf;		/* output ciphertext */
	static unsigned int bufsize;	/* size of outbuf */
	ftp_int32 length;
	ftp_uint32 net_len;

	/* Other auth types go here ... */
#ifdef KRB5_KRB4_COMPAT
	if (bufsize < nbyte + FUDGE_FACTOR) {
		if (outbuf?
		    (outbuf = realloc(outbuf, (unsigned) (nbyte + FUDGE_FACTOR))):
		    (outbuf = malloc((unsigned) (nbyte + FUDGE_FACTOR)))) {
		  			bufsize =nbyte + FUDGE_FACTOR;
		} else {
			bufsize = 0;
			secure_error("%s (in malloc of PROT buffer)",
				     sys_errlist[errno]);
			return(ERR);
		}
	}

	if (strcmp(auth_type, "KERBEROS_V4") == 0)
	  if ((length = level == PROT_P ?
	    krb_mk_priv(buf, (unsigned char *) outbuf, nbyte, schedule,
			SESSION, &myaddr, &hisaddr)
	  : krb_mk_safe(buf, (unsigned char *) outbuf, nbyte, SESSION,
			&myaddr, &hisaddr)) == -1) {
		secure_error("krb_mk_%s failed for KERBEROS_V4",
				level == PROT_P ? "priv" : "safe");
		return(ERR);
	  }
#endif /* KRB5_KRB4_COMPAT */
#ifdef GSSAPI
	if (strcmp(auth_type, "GSSAPI") == 0) {
		gss_buffer_desc in_buf, out_buf;
		OM_uint32 maj_stat, min_stat;
		int conf_state;
		
		in_buf.value = buf;
		in_buf.length = nbyte;
		maj_stat = gss_seal(&min_stat, gcontext,
				    (level == PROT_P), /* confidential */
				    GSS_C_QOP_DEFAULT,
				    &in_buf, &conf_state,
				    &out_buf);
		if (maj_stat != GSS_S_COMPLETE) {
			/* generally need to deal */
			/* ie. should loop, but for now just fail */
			secure_gss_error(maj_stat, min_stat,
					 level == PROT_P?
					 "GSSAPI seal failed":
					 "GSSAPI sign failed");
			return(ERR);
		}

		if (bufsize < out_buf.length) {
			if (outbuf?
			    (outbuf = realloc(outbuf, (unsigned) out_buf.length)):
			    (outbuf = malloc((unsigned) out_buf.length))) {
				bufsize = nbyte + FUDGE_FACTOR;
			} else {
				bufsize = 0;
				secure_error("%s (in malloc of PROT buffer)",
					     sys_errlist[errno]);
				return(ERR);
			}
		}

		memcpy(outbuf, out_buf.value, length=out_buf.length);
		gss_release_buffer(&min_stat, &out_buf);
	}
#endif /* GSSAPI */
	net_len = htonl((u_long) length);
	if (looping_write(fd, &net_len, 4) == -1) return(-1);
	if (looping_write(fd, outbuf, length) != length) return(-1);
	return(0);
}

static
secure_getbyte(fd)
int fd;
{
	/* number of chars in ucbuf, pointer into ucbuf */
	static unsigned int nin, bufp;
	int kerror;
	ftp_uint32 length;

	if (nin == 0) {
		if ((kerror = looping_read(fd, &length, sizeof(length)))
				!= sizeof(length)) {
			secure_error("Couldn't read PROT buffer length: %d/%s",
				     kerror,
				     kerror == -1 ? sys_errlist[errno]
				     : "premature EOF");
			return(ERR);
		}
		if ((length = (u_long) ntohl(length)) > MAX) {
			secure_error("Length (%d) of PROT buffer > PBSZ=%u", 
				     length, MAX);
			return(ERR);
		}
		if ((kerror = looping_read(fd, ucbuf, length)) != length) {
			secure_error("Couldn't read %u byte PROT buffer: %s",
					length, kerror == -1 ?
					sys_errlist[errno] : "premature EOF");
			return(ERR);
		}
		/* Other auth types go here ... */
#ifdef KRB5_KRB4_COMPAT
		if (strcmp(auth_type, "KERBEROS_V4") == 0) {
		  if (kerror = level == PROT_P ?
		    krb_rd_priv(ucbuf, length, schedule, SESSION,
				&hisaddr, &myaddr, &msg_data)
		  : krb_rd_safe(ucbuf, length, SESSION,
				&hisaddr, &myaddr, &msg_data)) {
			secure_error("krb_rd_%s failed for KERBEROS_V4 (%s)",
					level == PROT_P ? "priv" : "safe",
					krb_get_err_text(kerror));
			return(ERR);
		  }
		  memcpy(ucbuf, msg_data.app_data, msg_data.app_length);
		  nin = bufp = msg_data.app_length;
		}
#endif /* KRB5_KRB4_COMPAT */
#ifdef GSSAPI
		if (strcmp(auth_type, "GSSAPI") == 0) {
		  gss_buffer_desc xmit_buf, msg_buf;
		  OM_uint32 maj_stat, min_stat;
		  int conf_state;

		  xmit_buf.value = ucbuf;
		  xmit_buf.length = length;
		  conf_state = (level == PROT_P);
		  /* decrypt/verify the message */
		  maj_stat = gss_unseal(&min_stat, gcontext, &xmit_buf,
					&msg_buf, &conf_state, NULL);
		  if (maj_stat != GSS_S_COMPLETE) {
		    secure_gss_error(maj_stat, min_stat, 
				     (level == PROT_P)?
				     "failed unsealing ENC message":
				     "failed unsealing MIC message");
		    return ERR;
		  }

		  memcpy(ucbuf, msg_buf.value, nin = bufp = msg_buf.length);
		  gss_release_buffer(&min_stat, &msg_buf);
	      }
#endif /* GSSAPI */
		/* Other auth types go here ... */
	}
	if (nin == 0)
		return(EOF);
	else	return(ucbuf[bufp - nin--]);
}

/* returns:
 *	c>=0 on success
 *	-1   on EOF
 *	-2   on security error
 */
secure_getc(stream)
FILE *stream;
{
	if (level == PROT_C)
		return(getc(stream));
	return(secure_getbyte(fileno(stream)));
}

/* returns:
 *	n>0 on success (n == # of bytes read)
 *	0   on EOF
 *	-1  on error (errno set), only for PROT_C
 *	-2  on security error
 */
secure_read(fd, buf, nbyte)
int fd;
char *buf;
int nbyte;
{
	static int c;
	int i;

	if (level == PROT_C)
		return(read(fd,buf,nbyte));
	if (c == EOF)
		return(c = 0);
	for (i=0; nbyte>0; nbyte--)
		switch (c = secure_getbyte(fd)) {
			case ERR: return(c);
			case EOF: if (!i) c = 0;
				  return(i);
			default:  buf[i++] = c;
		}
	return(i);
}
