/*			Networked				*/
/*								*/
/* Written by:	Glenn Machin 2931				*/
/* Originated:  Nov 12, 1990					*/
/* Description:							*/
/*								*/
/*	This program/routine exits/returns with a status 1 if	*/
/*	the terminal associated with the current process is	*/
/*	connected from a remote host, otherwise exits/returns	*/
/*	with a value of 0.					*/
/*								*/
/*	This program/routine makes some basic assumptions about	*/
/*      utmp:							*/
/*      	*The login process, rcmd, or window application */
/*		 makes an entry into utmp for all currents 	*/
/*		 users.						*/
/*		*For entries in which the users have logged in  */
/*		 locally. The line name is not a pseudo tty     */
/*		 device. 					*/
/*		*For X window application in which 	       */
/*		 the device is a pseudo tty device but the      */
/*               display is the local system, then the ut_host  */
/*	         has the format system_name:0.0 or :0.0.        */
/*		 All other entries will be assumed to be        */
/*		 networked.				        */
/*								*/
/*	Changes:   11/15/90  Check for file /etc/krb.secure.    */
/*			     If it exists then perform network  */
/*			     check, otherwise return 0.		*/
/****************************************************************/
/* 
 * Sandia National Laboratories also makes no representations about the 
 * suitability of the modifications, or additions to this software for 
 * any purpose.  It is provided "as is" without express or implied warranty.
 */
#ifndef _TYPES_
#include <sys/types.h>
#ifndef _TYPES_
#define _TYPES_
#endif
#endif
#include <utmp.h>
#include <pwd.h>

#ifndef MAXHOSTNAME
#define MAXHOSTNAME 64
#endif

int utfile;			/* Global utfile file descriptor for BSD version
				   of setutent, getutline, and endutent */

#if !defined(SYSV) && !defined(UMIPS)	/* Setutent, Endutent, and getutline
					   routines for non System V Unix
						 systems */
#include <fcntl.h>

void setutent()
{
  utfile = open("/etc/utmp",O_RDONLY);
}

struct utmp * getutline(utmpent)
struct utmp *utmpent;
{
 static struct utmp tmputmpent;
 int found = 0;
 while ( read(utfile,&tmputmpent,sizeof(struct utmp)) > 0 ){
	if ( strcmp(tmputmpent.ut_line,utmpent->ut_line) == 0){
#ifdef NO_UT_HOST
		if ( ( 1) &&
#else
		if ( (strcmp(tmputmpent.ut_host,"") == 0) && 
#endif
	     	   (strcmp(tmputmpent.ut_name,"") == 0)) continue;
		found = 1;
		break;
	}
 }
 if (found) 
	return(&tmputmpent);
 return((struct utmp *) 0);
}

void endutent()
{
  close(utfile);
}
#endif /* not SYSV */


int network_connected()
{
struct utmp utmpent;
struct utmp retutent, *tmpptr;
char *display_indx;
char currenthost[MAXHOSTNAME];
char *username,*tmpname;


/* Macro for pseudo_tty */
#define pseudo_tty(ut) \
        ((strncmp((ut).ut_line, "tty", 3) == 0 && ((ut).ut_line[3] == 'p' \
                                                || (ut).ut_line[3] == 'q' \
                                                || (ut).ut_line[3] == 'r' \
                                                || (ut).ut_line[3] == 's'))\
				|| (strncmp((ut).ut_line, "pty", 3) == 0))

    /* Check to see if getlogin returns proper name */
    if ( (tmpname = (char *) getlogin()) == (char *) 0) return(1);
    username = (char *) malloc(strlen(tmpname) + 1);
    if ( username == (char *) 0) return(1);
    strcpy(username,tmpname);
    
    /* Obtain tty device for controlling tty of current process.*/
    strncpy(utmpent.ut_line,ttyname(0) + strlen("/dev/"),
	    sizeof(utmpent.ut_line));

    /* See if this device is currently listed in /etc/utmp under
       calling user */
#ifdef SYSV
    utmpent.ut_type = USER_PROCESS;
#define ut_name ut_user
#endif
    setutent();
    while ( (tmpptr = (struct utmp *) getutline(&utmpent)) 
            != ( struct utmp *) 0) {

	/* If logged out name and host will be empty */
	if ((strcmp(tmpptr->ut_name,"") == 0) &&
#ifdef NO_UT_HOST
	    ( 1)) continue;
#else
	    (strcmp(tmpptr->ut_host,"") == 0)) continue;
#endif
	else break;
    }
    if (  tmpptr   == (struct utmp *) 0) {
	endutent();
	return(1);
    }
    byte_copy((char *)tmpptr,(char *)&retutent,sizeof(struct utmp));
    endutent();
#ifdef DEBUG
#ifdef NO_UT_HOST
    printf("User %s on line %s :\n",
		retutent.ut_name,retutent.ut_line);
#else
    printf("User %s on line %s connected from host :%s:\n",
		retutent.ut_name,retutent.ut_line,retutent.ut_host);
#endif
#endif
    if  (strcmp(retutent.ut_name,username) != 0) {
	 return(1);
    }


    /* If this is not a pseudo tty then everything is OK */
    if (! pseudo_tty(retutent)) return(0);

    /* OK now the work begins there is an entry in utmp and
       the device is a pseudo tty. */

    /* Check if : is in hostname if so this is xwindow display */

    if (gethostname(currenthost,sizeof(currenthost))) return(1);
#ifdef NO_UT_HOST
    display_indx = (char *) 0;
#else
    display_indx = (char *) strchr(retutent.ut_host,':');
#endif
    if ( display_indx != (char *) 0) {
        /* 
           We have X window application here. The host field should have
	   the form => local_system_name:0.0 or :0.0  
           if the window is being displayed on the local system.
         */
#ifdef NO_UT_HOST
	return(1);
#else
        if (strncmp(currenthost,retutent.ut_host,
                (display_indx - retutent.ut_host)) != 0) return(1);
        else return(0);
#endif
    }
    
    /* Host field is empty or is not X window entry. At this point
       we can't trust that the pseudo tty is not connected to a 
       networked process so let's return 1.
     */
    return(1);
}

byte_copy(str1,str2,len)
char *str1, *str2;
int len;
{
 int i;
 for (i=0;i < len; i++) *(str2 + i) = *(str1 + i);
 return;
}


#ifdef NOTKERBEROS
main(argc,argv)
int argc;
char **argv;
{
  if (network_connected()){
#ifdef DEBUG
	 printf("Networked\n");
#endif
	exit(1);
  }
  else {
#ifdef DEBUG
	printf("Not networked\n");
#endif
	exit(0);
  }
}
#else
int networked()
{
  return(network_connected());
}
#endif
