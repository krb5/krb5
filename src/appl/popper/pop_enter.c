
/*
 * 
 */
 
#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#else
#include <string.h>
#endif
#include <sys/stat.h>
#include <sys/file.h>
#include <mit-copyright.h>

#ifdef ZEPHYR
#include <zephyr/zephyr.h>

char *Zsignature = "Your friendly neighborhood post office.";
#endif ZEPHYR

void notify_recipient();

char buffer[BUFSIZ];
char xtmpfile[512];           /* tmp file */
int  newmail;                /* fd for temp message */
int  maildrop;               /* file descriptor for drop */

extern int errno;
extern int sys_nerr;
extern char *sys_errlist[];


main (argc, argv)
     int argc;
     char **argv;     
{
  int status = 0;
  int  i = 1;                  /* argument counter */
      
  if(get_message() < 0)
    exit(1);

  while (--argc > 0) 
    {
      if(open_drop(argv[i]) < 0)
	{
	  lseek(newmail, (off_t)0, SEEK_SET);
	  if(new_message(maildrop, newmail) < 0)
	    status = 1;
	  if(close(maildrop) < 0)
	    {
	      status = 1;
	      sprintf(buffer, "%s: error on close", argv[i]);
	      error(buffer, errno);
	    }
	  notify_recipient(argv[i]);
	}
      else
	status = 1;
      ++i;
    }
  
  close(newmail);
  unlink(xtmpfile);
  exit(status);
}



int
get_message()
{
  int  nchar;        

  sprintf(xtmpfile, "/tmp/tpop.%d", getpid());
  if((newmail = open(xtmpfile, O_RDWR|O_CREAT, 0600)) == -1) 
    {
      fprintf(stderr, "unable to open temporary file,  \"%s\".\n",  xtmpfile);
      return(-1);
    }
    
  while(nchar = read(0, buffer, sizeof(buffer)))
    write(newmail, buffer, nchar);  

  return(0);
}



int
open_drop(name)
     char *name;
{
  char dropfile[512];             

  sprintf(dropfile, "%s/%s", MAILDIR, name);
  if ((maildrop = open(dropfile, O_RDWR|O_CREAT,0600)) == -1)  
    {
      fprintf(stderr, "unable to open \"%s\": %s.\n", 
	      dropfile, (errno < sys_nerr) ? sys_errlist[errno] : "");
      return(-1);
    }
  
  /*  Lock the user's real mail drop */
  
  if (flock(maildrop, LOCK_EX) == -1) 
    {
      fprintf(stderr, 
	   "unable to lock \"%s\" (service unavailable... the sequel): %s.\n", 
	      dropfile, (errno < sys_nerr) ? 
	      sys_errlist[errno] : "");
      return(-1);
    }

  lseek(maildrop, (off_t)0, SEEK_END);
  return(0);
}



new_message(to, from)
     int to, from;
{
  int cc;
  
  cc = time(0);
  sprintf(buffer, "From popper %s\n", ctime(&cc)); 
  write(to, buffer, strlen(buffer) * sizeof(char));
  while(cc = read(from, buffer, sizeof(buffer)))
    write(to, buffer, cc);
  write(to, "\n", 1);
}
      


void
notify_recipient(name)
     char *name;
     
{
  char *message = "You have new mail";

#ifdef ZEPHYR
  static int init = 0;
  ZNotice_t notice;             /* Zephyr notice */
  int    ret;                   /* return value, length */
  
  if(init)
    if ((ret = ZInitialize()) == ZERR_NONE)
      init = 0;

  memset(&notice, 0, sizeof(notice));
  notice.z_kind = UNSAFE;
  notice.z_class          = "message";
  notice.z_class_inst     = "pop";
  notice.z_recipient      = name;

  zsend(&notice, &message, 1, 1);
#endif ZEPHYR
}



#ifdef ZEPHYR
zsend(notice, items, nitems, auth)
     ZNotice_t *notice;
     char **items;
     int nitems;
     int auth;
{
  int ret;

  if ((ret = ZSendList(notice, items, nitems, auth ? ZAUTH:ZNOAUTH)) !=
      ZERR_NONE)
    { /* syslog */
      if(auth) 
        return(zsend(notice, items, nitems, 0));
      else
        return(-1);
    }
}

#endif ZEPHYR
  
  
