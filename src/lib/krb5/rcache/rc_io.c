/*
 * lib/krb5/rcache/rc_io.c
 *
 * This file of the Kerberos V5 software is derived from public-domain code
 * contributed by Daniel J. Bernstein, <brnstnd@acf10.nyu.edu>.
 *
 */


/*
 * I/O functions for the replay cache default implementation.
 */


#define KRB5_RC_VNO	0x0501		/* krb5, rcache v 1 */
#define NEED_SOCKETS
#define NEED_LOWLEVEL_IO         

#include <krb5.h>
#include <stdio.h> /* for P_tmpdir */
#include "rc_base.h"
#include "rc_dfl.h"
#include "rc_io.h"

#ifndef O_BINARY
#define O_BINARY    0
#endif

#ifdef KRB5_USE_INET
#if !defined(_WINSOCKAPI_) && !defined(HAVE_MACSOCK_H)
#include <netinet/in.h>
#endif
#else
 #error find some way to use net-byte-order file version numbers.
#endif

#ifndef HAVE_ERRNO
extern int errno; /* this should be in errno.h, but isn't on some systems */
#endif

#define FREE(x) ((void) free((char *) (x)))
#define UNIQUE getpid() /* hopefully unique number */

static int dirlen = 0;
static char *dir;

/* The do ... while(0) is required to insure that GETDIR looks like a
   single statement in all situations (just {}'s may cause troubles in
   certain situations, such as nested if/else clauses. */

#define GETDIR do { if (!dirlen) getdir(); } while(0)

static void getdir()
{
 if (!dirlen)
  {
   if (!(dir = getenv("KRB5RCACHEDIR")))
     if (!(dir = getenv("TMPDIR")))
#ifdef RCTMPDIR
       dir = RCTMPDIR;
#else
       dir = "/tmp";
#endif
   dirlen = strlen(dir) + 1;
  }
}

krb5_error_code krb5_rc_io_creat (context, d, fn)
    krb5_context context;
    krb5_rc_iostuff *d;
    char **fn;
{
 char *c;
 krb5_int16 rc_vno = htons(KRB5_RC_VNO);
 krb5_error_code retval;

 GETDIR;
 if (fn && *fn)
  {
   if (!(d->fn = malloc(strlen(*fn) + dirlen + 1)))
     return KRB5_RC_IO_MALLOC;
   (void) strcpy(d->fn,dir);
   (void) strcat(d->fn,"/");
   (void) strcat(d->fn,*fn);
   d->fd = THREEPARAMOPEN(d->fn,O_WRONLY | O_CREAT | O_TRUNC | O_EXCL | O_BINARY,0600);
  }
 else
  {
      /* %d is max 11 digits (-, 10 digits of 32-bit number)
	 * 11 + /krb5_RC + aaa = 24, +6 for slop */
   if (!(d->fn = malloc(30 + dirlen)))
     return KRB5_RC_IO_MALLOC;
   if (fn)
     if (!(*fn = malloc(35)))
      { FREE(d->fn); return KRB5_RC_IO_MALLOC; }
   (void) sprintf(d->fn,"%s/krb5_RC%d",dir,UNIQUE);
   c = d->fn + strlen(d->fn);
   (void) strcpy(c,"aaa");
   while ((d->fd = THREEPARAMOPEN(d->fn,O_WRONLY|O_CREAT|O_TRUNC|O_EXCL|O_BINARY,0600)) == -1)
    {
     if ((c[2]++) == 'z')
      {
       c[2] = 'a';
       if ((c[1]++) == 'z')
	{
         c[1] = 'a';
         if ((c[0]++) == 'z')
           break; /* sigh */
        }
      }
    }
   if (fn)
     (void) strcpy(*fn,d->fn + dirlen);
  }
 if (d->fd == -1)
    {
   switch(errno)
    {
	case EFBIG: 
#ifdef EDQUOT
	case EDQUOT:
#endif
	case ENOSPC: 
	    retval = KRB5_RC_IO_SPACE; 
	    goto fail;
	case EIO: 
	    retval = KRB5_RC_IO_IO; goto fail;

	case EPERM: 
	case EACCES: 
	case EROFS: 
	case EEXIST: 
	    retval = KRB5_RC_IO_PERM; goto no_unlink;

	default: 
	    retval = KRB5_RC_IO_UNKNOWN; goto fail;
    }
    }
    if ((retval = krb5_rc_io_write(context, d, (krb5_pointer)&rc_vno, sizeof(rc_vno))) ||
	(retval = krb5_rc_io_sync(context, d)))
    {
    fail:
     (void) unlink(d->fn);
    no_unlink:
     FREE(d->fn);
	d->fn = NULL;
     (void) close(d->fd);
     return retval;
 }
 return 0;
}

krb5_error_code krb5_rc_io_open (context, d, fn)
    krb5_context context;
    krb5_rc_iostuff *d;
    char *fn;
{
 krb5_int16 rc_vno;
 krb5_error_code retval;
#ifndef NO_USERID
 struct stat statb;
#endif

 GETDIR;
 if (!(d->fn = malloc(strlen(fn) + dirlen + 1)))
   return KRB5_RC_IO_MALLOC;
 (void) strcpy(d->fn,dir);
 (void) strcat(d->fn,"/");
 (void) strcat(d->fn,fn);

#ifdef NO_USERID
 d->fd = THREEPARAMOPEN(d->fn,O_RDWR | O_BINARY,0600);
#else
 if ((d->fd = stat(d->fn, &statb)) != -1) {
     uid_t me;

     me = getuid();
     /* must be owned by this user, to prevent some security problems with
	 * other users modifying replay cache stufff */
     if ((statb.st_uid != me) || ((statb.st_mode & S_IFMT) != S_IFREG)) {
	 FREE(d->fn);
	 return KRB5_RC_IO_PERM;
     }
     d->fd = THREEPARAMOPEN(d->fn,O_RDWR | O_BINARY,0600);
 }
#endif
 if (d->fd == -1) {
   switch(errno)
    {
	case EFBIG: 
#ifdef EDQUOT
	case EDQUOT:
#endif
	case ENOSPC:
	    retval = KRB5_RC_IO_SPACE; 
	    goto fail;

	case EIO: 
	    retval = KRB5_RC_IO_IO; 
	    goto fail;

	case EPERM: 
	case EACCES:
	case EROFS: 
	    retval = KRB5_RC_IO_PERM; 
	    goto fail;

	    default: 
	    retval = KRB5_RC_IO_UNKNOWN; 
	    goto fail;
    }
 }
    if ((retval = krb5_rc_io_read(context, d, (krb5_pointer) &rc_vno,
				  sizeof(rc_vno))))
	goto unlk;


    if (ntohs(rc_vno) != KRB5_RC_VNO) 
    {
	retval = KRB5_RCACHE_BADVNO;
    unlk:
	unlink(d->fn);
    fail:
     (void) close(d->fd);
     FREE(d->fn); 
	d->fn = NULL;
     return retval;
 }
 return 0;
}

krb5_error_code krb5_rc_io_move (context, new, old)
    krb5_context context;
    krb5_rc_iostuff *new;
    krb5_rc_iostuff *old;
{
 if (rename(old->fn,new->fn) == -1) /* MUST be atomic! */
   return KRB5_RC_IO_UNKNOWN;
 (void) krb5_rc_io_close(context, new);
 new->fn = malloc(strlen(old->fn)+1);
 if (new->fn == 0)
   return ENOMEM;
 strcpy(new->fn, old->fn);
#ifdef _MACINTOSH
 new->fd = fcntl(old->fd, F_DUPFD);
#else
 new->fd = dup(old->fd);
#endif
 return 0;
}

krb5_error_code krb5_rc_io_write (context, d, buf, num)
    krb5_context context;
    krb5_rc_iostuff *d;
    krb5_pointer buf;
    int num;
{
 if (write(d->fd,(char *) buf,num) == -1)
   switch(errno)
    {
     case EBADF: return KRB5_RC_IO_UNKNOWN; 
     case EFBIG: return KRB5_RC_IO_SPACE; 
#ifdef EDQUOT
     case EDQUOT: return KRB5_RC_IO_SPACE; 
#endif
     case ENOSPC: return KRB5_RC_IO_SPACE; 
     case EIO: return KRB5_RC_IO_IO; 
     default: return KRB5_RC_IO_UNKNOWN; 
    }
 return 0;
}

krb5_error_code krb5_rc_io_sync (context, d)
    krb5_context context;
    krb5_rc_iostuff *d;
{
#if !defined(MSDOS_FILESYSTEM) && !defined(_MACINTOSH)
    if (fsync(d->fd) == -1) {
      switch(errno)
      {
      case EBADF: return KRB5_RC_IO_UNKNOWN; 
      case EIO: return KRB5_RC_IO_IO; 
      default: return KRB5_RC_IO_UNKNOWN; 
      }
    }
#endif
    return 0;
}

krb5_error_code krb5_rc_io_read (context, d, buf, num)
    krb5_context context;
    krb5_rc_iostuff *d;
    krb5_pointer buf;
    int num;
{
 int count;
 if ((count = read(d->fd,(char *) buf,num)) == -1)
   switch(errno)
    {
     case EBADF: return KRB5_RC_IO_UNKNOWN; 
     case EIO: return KRB5_RC_IO_IO; 
     default: return KRB5_RC_IO_UNKNOWN; 
    }
 if (count == 0)
     return KRB5_RC_IO_EOF;
 return 0;
}

krb5_error_code krb5_rc_io_close (context, d)
    krb5_context context;
    krb5_rc_iostuff *d;
{
 FREE(d->fn);
 d->fn = NULL;
 if (close(d->fd) == -1) /* can't happen */
   return KRB5_RC_IO_UNKNOWN;
 return 0;
}

krb5_error_code krb5_rc_io_destroy (context, d)
    krb5_context context;
    krb5_rc_iostuff *d;
{
 if (unlink(d->fn) == -1)
   switch(errno)
    {
     case EBADF: return KRB5_RC_IO_UNKNOWN; 
     case EIO: return KRB5_RC_IO_IO; 
     case EPERM: return KRB5_RC_IO_PERM; 
     case EBUSY: return KRB5_RC_IO_PERM; 
     case EROFS: return KRB5_RC_IO_PERM; 
     default: return KRB5_RC_IO_UNKNOWN; 
    }
 return 0;
}

krb5_error_code krb5_rc_io_mark (context, d)
    krb5_context context;
    krb5_rc_iostuff *d;
{
 d->mark = lseek(d->fd,0,SEEK_CUR); /* can't fail */
 return 0;
}

krb5_error_code krb5_rc_io_unmark (context, d)
    krb5_context context;
    krb5_rc_iostuff *d;
{
 (void) lseek(d->fd,d->mark,SEEK_SET); /* if it fails, tough luck */
 return 0;
}

long
krb5_rc_io_size (context, d)
    krb5_context context;
    krb5_rc_iostuff *d;
{
    struct stat statb;
    
    if (fstat (d->fd, &statb) == 0)
	return statb.st_size;
    else
	return 0;
}
    
