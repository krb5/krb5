/*
 * Copyright (c) 1989 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#ifndef lint
static char copyright[] = "Copyright (c) 1990 Regents of the University of California.\nAll rights reserved.\n";
static char SccsId[] = "@(#)pop_dropcopy.c  1.2 7/13/90";
#endif not lint

#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/file.h>
#include "popper.h"

extern int      errno;
extern int      sys_nerr;
extern char    *sys_errlist[];

#define LOCK_RETRY 3
#define LOCK_WAIT  5

/* 
 *  dropcopy:   Make a temporary copy of the user's mail drop and 
 *  save a stream pointer for it.
 */

pop_dropcopy(p)
POP     *   p;
{
    int                     mfd;                    /*  File descriptor for 
                                                        the user's maildrop */
    int                     dfd;                    /*  File descriptor for 
                                                        the SERVER maildrop */
    char                    buffer[BUFSIZ];         /*  Read buffer */
    long                    offset;                 /*  Old/New boundary */
    int                     nchar;                  /*  Bytes written/read */
    int                     locked;                 /*  if drop is loced */
    int                     retry = 0;              /*  times to retry lock */

    /*  Create a temporary maildrop into which to copy the updated maildrop */
    (void)sprintf(p->temp_drop,POP_DROP,p->user);

#ifdef DEBUG
    if(p->debug)
        pop_log(p,POP_DEBUG,"Creating temporary maildrop '%s'",
            p->temp_drop);
#endif DEBUG

    /* Open for append,  this solves the crash recovery problem */
    if ((dfd = open(p->temp_drop,O_RDWR|O_APPEND|O_CREAT,0666)) == -1){
        pop_log(p,POP_ERROR,
            "%s: (%s) unable to create temporary maildrop: %s",
		p->client, p->temp_drop,
                (errno < sys_nerr) ? sys_errlist[errno] : "") ;
        return (POP_FAILURE);
    }

    /*  Lock the temporary maildrop. Try a few times if it doesn't succeed. */
    
    locked = 1;
    while(locked) {
        if ( flock (dfd, LOCK_EX|LOCK_NB) == -1 )            
	    switch(errno) {
	    case EWOULDBLOCK:
	      if(retry++ < LOCK_RETRY)  {
		  sleep(LOCK_WAIT);
		  continue;
	      }
	      pop_log(p, POP_PRIORITY, "%s: (%s) maildrop locked", 
		      p->client, p->temp_drop);
	      return pop_msg(p,POP_FAILURE,
		 "Maildrop for %s is busy. Please try again in a few moments.",
			     p->user);
	      /* NOTREACHED */

	    default:
	      pop_log(p, POP_PRIORITY, "%s: (%s) flock: %s", p->client, 
		      p->temp_drop,
		      (errno < sys_nerr) ? sys_errlist[errno] : "");
	      return pop_msg(p,POP_FAILURE,"flock: '%s': %s", p->temp_drop,
			     (errno < sys_nerr) ? sys_errlist[errno] : "");
	      /* NOTREACHED */
	    }
	else
	  locked = 0;
    }

    /* May have grown or shrunk between open and lock! */
    offset = lseek(dfd,0,L_XTND);

    /*  Open the user's maildrop, If this fails,  no harm in assuming empty */
    if ((mfd = open(p->drop_name,O_RDWR)) > 0) {

        /*  Lock the maildrop */
        if (flock (mfd,LOCK_EX) == -1) {
            (void)close(mfd) ;
	    pop_log(p, POP_PRIORITY, "%s: (%s) flock: %s", p->client, 
		    p->drop_name,(errno < sys_nerr) ? sys_errlist[errno] : "");
            return pop_msg(p,POP_FAILURE, "flock: '%s': %s", p->temp_drop,
                (errno < sys_nerr) ? sys_errlist[errno] : "");
        }

        /*  Copy the actual mail drop into the temporary mail drop */
        while ( (nchar=read(mfd,buffer,BUFSIZ)) > 0 )
            if ( nchar != write(dfd,buffer,nchar) ) {
                nchar = -1 ;
                break ;
            }

        if ( nchar != 0 ) {
            /* Error adding new mail.  Truncate to original size,
               and leave the maildrop as is.  The user will not 
               see the new mail until the error goes away.
               Should let them process the current backlog,  in case
               the error is a quota problem requiring deletions! */
            (void)ftruncate(dfd,(int)offset) ;
        } else {
            /* Mail transferred!  Zero the mail drop NOW,  that we
               do not have to do gymnastics to figure out what's new
	       and what is old later */
            (void)ftruncate(mfd,0) ;
        }

        /*  Close the actual mail drop */
        (void)close (mfd);
    }

    /*  Acquire a stream pointer for the temporary maildrop */
    if ( (p->drop = fdopen(dfd,"a+")) == NULL ) {
        (void)close(dfd) ;
	pop_log(p, POP_PRIORITY, "%s: (%s) fdopen: %s", p->client, 
		p->temp_drop, (errno < sys_nerr) ? sys_errlist[errno] : "");
        return pop_msg(p,POP_FAILURE,"Cannot assign stream for %s",
            p->temp_drop);
    }

    rewind (p->drop);

#ifdef DEBUG
    if (!p->debug)
        unlink (p->temp_drop);
#endif DEBUG

    return(POP_SUCCESS);
}
