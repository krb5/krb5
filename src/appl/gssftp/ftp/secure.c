/*
 * Shared routines for client and server for
 * secure read(), write(), getc(), and putc().
 * Only one security context, thus only work on one fd at a time!
 */
#ifdef GSSAPI
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_generic.h>
extern gss_ctx_id_t gcontext;
#endif /* GSSAPI */

#include <secure.h>	/* stuff which is specific to client or server */

#ifdef KRB5_KRB4_COMPAT
#include <krb.h>

CRED_DECL
extern KTEXT_ST ticket;
extern MSG_DAT msg_data;
extern Key_schedule schedule;
#endif /* KRB5_KRB4_COMPAT */

#ifdef _WIN32
#undef ERROR
#endif

#include <arpa/ftp.h>

#include <stdio.h>
#include <string.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/types.h>
#ifdef _WIN32
#include <port-sockets.h>
#else
#include <netinet/in.h>
#endif
#include <errno.h>

#ifndef HAVE_STRERROR
#define strerror(error) (sys_errlist[error])
#ifdef NEED_SYS_ERRLIST
extern char *sys_errlist[];
#endif
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

static int secure_putbuf (int, unsigned char *, unsigned int);

extern struct	sockaddr_in hisaddr;
extern struct	sockaddr_in myaddr;
extern int	dlevel;
extern char	*auth_type;

/* Some libc's (GNU libc, at least) define MAX as a macro. Forget that. */
#ifdef MAX
#undef MAX
#endif

#define MAX maxbuf
extern unsigned int maxbuf; 	/* maximum output buffer size */
extern unsigned char *ucbuf;	/* cleartext buffer */
static unsigned int nout;	/* number of chars in ucbuf,
				 * pointer into ucbuf */
static unsigned int smaxbuf;    /* Internal saved value of maxbuf 
				   in case changes on us */
static unsigned int smaxqueue;  /* Maximum allowed to queue before 
				   flush buffer. < smaxbuf by fudgefactor */

#ifdef KRB5_KRB4_COMPAT
#define KRB4_FUDGE_FACTOR 32	/* Amount of growth
				 * from cleartext to ciphertext.
				 * krb_mk_priv adds this # bytes.
				 * Must be defined for each auth type.
				 */
#endif /* KRB5_KRB4_COMPAT */

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



#define ERR	-2

/* 
 * Given maxbuf as a buffer size, determine how much can we
 * really transfer given the overhead of different algorithms 
 *
 * Sets smaxbuf and smaxqueue
 */

static int secure_determine_constants()
{
    smaxbuf = maxbuf;
    smaxqueue = maxbuf;

#ifdef KRB5_KRB4_COMPAT
    /* For KRB4 - we know the fudge factor to be 32 */
    if (strcmp(auth_type, "KERBEROS_V4") == 0) {
	smaxqueue = smaxbuf - KRB4_FUDGE_FACTOR;
    }
#endif
#ifdef GSSAPI
    if (strcmp(auth_type, "GSSAPI") == 0) {
	OM_uint32 maj_stat, min_stat, mlen;
	OM_uint32 msize = maxbuf;
	maj_stat = gss_wrap_size_limit(&min_stat, gcontext, 
				       (dlevel == PROT_P),
				       GSS_C_QOP_DEFAULT,
				       msize, &mlen);
	if (maj_stat != GSS_S_COMPLETE) {
			secure_gss_error(maj_stat, min_stat, 
					 "GSSAPI fudge determination");
			/* Return error how? */
			return ERR;
	}
	smaxqueue = mlen;
    }
#endif
    
	return 0;
}

static int
secure_putbyte(fd, c)
int fd;
unsigned char c;
{
	int ret;

	if ((smaxbuf == 0) || (smaxqueue == 0) || (smaxbuf != maxbuf)) {
	    ret = secure_determine_constants();
	    if (ret) return ret;
	}
	ucbuf[nout++] = c;
	if (nout == smaxqueue) {
	  nout = 0;
	  ret = secure_putbuf(fd, ucbuf, smaxqueue);
	  return(ret?ret:c);
	}
	return (c);
}

/* returns:
 *	 0  on success
 *	-1  on error (errno set)
 *	-2  on security error
 */
int secure_flush(fd)
int fd;
{
	int ret;

	if (dlevel == PROT_C)
		return(0);
	if (nout) {
 	        ret = secure_putbuf(fd, ucbuf, nout);
		if (ret)
			return(ret);
	}
	return(secure_putbuf(fd, (unsigned char *) "", nout = 0));
}

/* returns:
 *	c>=0  on success
 *	-1    on error
 *	-2    on security error
 */
int secure_putc(c, stream)
int c;
FILE *stream;
{
	if (dlevel == PROT_C)
		return(putc(c,stream));
	return(secure_putbyte(fileno(stream), (unsigned char) c));
}

/* returns:
 *	nbyte on success
 *	-1  on error (errno set)
 *	-2  on security error
 */
int 
secure_write(fd, buf, nbyte)
int fd;
unsigned char *buf;
unsigned int nbyte;
{
	unsigned int i;
	int c;

	if (dlevel == PROT_C)
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
static int
secure_putbuf(fd, buf, nbyte)
  int fd;
unsigned char *buf;
unsigned int nbyte;
{
	static char *outbuf;		/* output ciphertext */
	static unsigned int bufsize;	/* size of outbuf */
	ftp_int32 length;
	ftp_uint32 net_len;
	unsigned int fudge = smaxbuf - smaxqueue; /* Difference in length
						     buffer lengths required */

	/* Other auth types go here ... */
#ifdef KRB5_KRB4_COMPAT
	if (bufsize < nbyte + fudge) {
		if (outbuf?
		    (outbuf = realloc(outbuf, (unsigned) (nbyte + fudge))):
		    (outbuf = malloc((unsigned) (nbyte + fudge)))) {
		    bufsize = nbyte + fudge;
		} else {
			bufsize = 0;
			secure_error("%s (in malloc of PROT buffer)",
				     strerror(errno));
			return(ERR);
		}
	}

	if (strcmp(auth_type, "KERBEROS_V4") == 0)
	  if ((length = dlevel == PROT_P ?
	    krb_mk_priv(buf, (unsigned char *) outbuf, nbyte, schedule,
			SESSION, &myaddr, &hisaddr)
	  : krb_mk_safe(buf, (unsigned char *) outbuf, nbyte, SESSION,
			&myaddr, &hisaddr)) == -1) {
		secure_error("krb_mk_%s failed for KERBEROS_V4",
				dlevel == PROT_P ? "priv" : "safe");
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
				    (dlevel == PROT_P), /* confidential */
				    GSS_C_QOP_DEFAULT,
				    &in_buf, &conf_state,
				    &out_buf);
		if (maj_stat != GSS_S_COMPLETE) {
			/* generally need to deal */
			/* ie. should loop, but for now just fail */
			secure_gss_error(maj_stat, min_stat,
					 dlevel == PROT_P?
					 "GSSAPI seal failed":
					 "GSSAPI sign failed");
			return(ERR);
		}

		if (bufsize < out_buf.length) {
			if (outbuf?
			    (outbuf = realloc(outbuf, (unsigned) out_buf.length)):
			    (outbuf = malloc((unsigned) out_buf.length))) {
				bufsize = out_buf.length;
			} else {
				bufsize = 0;
				secure_error("%s (in malloc of PROT buffer)",
					     strerror(errno));
				return(ERR);
			}
		}

		length=out_buf.length;
		memcpy(outbuf, out_buf.value, out_buf.length);
		gss_release_buffer(&min_stat, &out_buf);
	}
#endif /* GSSAPI */
	net_len = htonl((u_long) length);
	if (looping_write(fd, (char *) &net_len, 4) == -1) return(-1);
	if (looping_write(fd, outbuf, length) != length) return(-1);
	return(0);
}

static int
secure_getbyte(fd)
int fd;
{
	/* number of chars in ucbuf, pointer into ucbuf */
	static unsigned int nin, bufp;
	int kerror;
	ftp_uint32 length;

	if (nin == 0) {
		if ((kerror = looping_read(fd, (char *) &length,
				sizeof(length)))
				!= sizeof(length)) {
			secure_error("Couldn't read PROT buffer length: %d/%s",
				     kerror,
				     kerror == -1 ? strerror(errno)
				     : "premature EOF");
			return(ERR);
		}
		if ((length = (u_long) ntohl(length)) > MAX) {
			secure_error("Length (%d) of PROT buffer > PBSZ=%u", 
				     length, MAX);
			return(ERR);
		}
		if ((kerror = looping_read(fd, (char *) ucbuf, (int) length)) != length) {
			secure_error("Couldn't read %u byte PROT buffer: %s",
					length, kerror == -1 ?
					strerror(errno) : "premature EOF");
			return(ERR);
		}
		/* Other auth types go here ... */
#ifdef KRB5_KRB4_COMPAT
		if (strcmp(auth_type, "KERBEROS_V4") == 0) {
		  if ((kerror = dlevel == PROT_P ?
		    krb_rd_priv(ucbuf, length, schedule, SESSION,
				&hisaddr, &myaddr, &msg_data)
		  : krb_rd_safe(ucbuf, length, SESSION,
				&hisaddr, &myaddr, &msg_data))) {
			secure_error("krb_rd_%s failed for KERBEROS_V4 (%s)",
					dlevel == PROT_P ? "priv" : "safe",
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
		  conf_state = (dlevel == PROT_P);
		  /* decrypt/verify the message */
		  maj_stat = gss_unseal(&min_stat, gcontext, &xmit_buf,
					&msg_buf, &conf_state, NULL);
		  if (maj_stat != GSS_S_COMPLETE) {
		    secure_gss_error(maj_stat, min_stat, 
				     (dlevel == PROT_P)?
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
int secure_getc(stream)
FILE *stream;
{
	if (dlevel == PROT_C)
		return(getc(stream));
	return(secure_getbyte(fileno(stream)));
}

/* returns:
 *	n>0 on success (n == # of bytes read)
 *	0   on EOF
 *	-1  on error (errno set), only for PROT_C
 *	-2  on security error
 */
int secure_read(fd, buf, nbyte)
int fd;
char *buf;
unsigned int nbyte;
{
	static int c;
	int i;

	if (dlevel == PROT_C)
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
